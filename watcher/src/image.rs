use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use flate2::read::GzDecoder;
use reqwest::redirect::{Attempt, Policy};
use tokio::sync::mpsc;

use crate::measure;

const RELEASES: &str = "https://github.com/Dstack-TEE/meta-dstack/releases/download";
/// Hosts a release download may be served from.
const HOSTS: [&str; 2] = ["github.com", "release-assets.githubusercontent.com"];
/// The files `measure` reads; everything else in the archive, the root filesystem first, is skipped.
const KEPT: [&str; 5] = [
    "sha256sum.txt",
    "metadata.json",
    "ovmf.fd",
    "bzImage",
    "initramfs.cpio.gz",
];
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const USER_AGENT: &str = concat!("sealed-review-watcher/", env!("CARGO_PKG_VERSION"));

/// Where `watcher check` finds the image a bundle declares.
pub enum Images {
    /// An image directory given by hand.
    Dir(PathBuf),
    /// The cache `watcher image` fills, one directory per `os_image_hash`.
    Cache(PathBuf),
}

impl Images {
    pub fn dir_for(&self, os_image_hash: &[u8]) -> Option<PathBuf> {
        match self {
            Self::Dir(dir) => Some(dir.clone()),
            Self::Cache(root) => Some(cached(root, os_image_hash)).filter(|d| d.is_dir()),
        }
    }
}

/// `$XDG_CACHE_HOME/sealed-review/images`, else `~/.cache/sealed-review/images`.
pub fn default_cache() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .context("neither XDG_CACHE_HOME nor HOME is set")?;
    Ok(base.join("sealed-review").join("images"))
}

fn cached(root: &Path, os_image_hash: &[u8]) -> PathBuf {
    root.join(hex::encode(os_image_hash))
}

/// `dstack-nvidia-0.5.12` → `<releases>/v0.5.12/dstack-nvidia-0.5.12.tar.gz`.
pub fn release_url(image: &str) -> Result<String> {
    let (flavour, version) = image
        .rsplit_once('-')
        .with_context(|| format!("image name {image:?} has no version"))?;
    let well_formed = !flavour.is_empty()
        && flavour
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && version.split('.').count() == 3
        && version
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ensure!(well_formed, "image name {image:?} is not <flavour>-<x.y.z>");
    Ok(format!("{RELEASES}/v{version}/{image}.tar.gz"))
}

fn redirect(attempt: Attempt) -> reqwest::redirect::Action {
    let allowed = attempt.url().host_str().is_some_and(|h| HOSTS.contains(&h));
    if allowed && attempt.previous().len() < 5 {
        attempt.follow()
    } else {
        attempt.error("redirect outside the allowed hosts")
    }
}

/// Fetches the release `image` names into the cache unless a verified copy is already there.
pub async fn fetch(image: &str, os_image_hash: &[u8], root: &Path) -> Result<PathBuf> {
    let dir = cached(root, os_image_hash);
    if measure::verify_image(&dir, os_image_hash).is_ok() {
        return Ok(dir);
    }
    let url = release_url(image)?;
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let partial = root.join(format!("{}.partial", hex::encode(os_image_hash)));
    if partial.exists() {
        std::fs::remove_dir_all(&partial)?;
    }
    std::fs::create_dir(&partial)?;

    let outcome = download(&url, &partial)
        .await
        .and_then(|()| measure::verify_image(&partial, os_image_hash).map(|_| ()));
    if let Err(e) = outcome {
        std::fs::remove_dir_all(&partial)?;
        return Err(e.context(format!("fetching {url}")));
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::rename(&partial, &dir)?;
    Ok(dir)
}

/// Streams the archive into the extractor; stops as soon as every kept file is written.
async fn download(url: &str, out: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(Policy::custom(redirect))
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .user_agent(USER_AGENT)
        .build()?;
    let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(32);
    let target = out.to_path_buf();
    let extractor = tokio::task::spawn_blocking(move || extract(Channel::new(rx), &target));

    if let Err(e) = stream(&client, url, &tx).await {
        let _ = tx.send(Err(io::Error::other(format!("{e:#}")))).await;
    }
    drop(tx);
    extractor.await?
}

async fn stream(
    client: &reqwest::Client,
    url: &str,
    tx: &mpsc::Sender<io::Result<Vec<u8>>>,
) -> Result<()> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut total: u64 = 0;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len() as u64;
        ensure!(
            total <= MAX_ARCHIVE_BYTES,
            "archive larger than {MAX_ARCHIVE_BYTES} bytes"
        );
        if tx.send(Ok(chunk.to_vec())).await.is_err() {
            break;
        }
    }
    Ok(())
}

/// Writes the kept files, by bare name, from a `.tar.gz`; anything else is never written.
fn extract(archive: impl Read, out: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(archive));
    let mut found: Vec<&str> = Vec::with_capacity(KEPT.len());
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?;
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| KEPT.iter().copied().find(|k| *k == n))
        else {
            continue;
        };
        ensure!(path.components().count() <= 2, "{name} is nested too deep");
        ensure!(
            !found.contains(&name),
            "{name} appears twice in the archive"
        );
        ensure!(
            entry.size() <= MAX_FILE_BYTES,
            "{name} is larger than {MAX_FILE_BYTES} bytes"
        );
        let mut file = std::fs::File::create(out.join(name))?;
        io::copy(&mut entry.by_ref().take(MAX_FILE_BYTES), &mut file)?;
        found.push(name);
        if found.len() == KEPT.len() {
            return Ok(());
        }
    }
    let missing: Vec<&str> = KEPT.into_iter().filter(|k| !found.contains(k)).collect();
    bail!("archive lacks {}", missing.join(", "))
}

/// Adapts the download channel to the blocking `Read` the gzip and tar decoders need.
struct Channel {
    rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    chunk: Vec<u8>,
    at: usize,
}

impl Channel {
    fn new(rx: mpsc::Receiver<io::Result<Vec<u8>>>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            at: 0,
        }
    }
}

impl Read for Channel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at == self.chunk.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.chunk = chunk?;
                    self.at = 0;
                }
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.chunk.len() - self.at);
        buf[..n].copy_from_slice(&self.chunk[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn all_kept(prefix: &str) -> Vec<(String, Vec<u8>)> {
        KEPT.iter()
            .map(|k| (format!("{prefix}{k}"), k.as_bytes().to_vec()))
            .collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("watcher-image-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn release_url_from_image_name() {
        assert_eq!(
            release_url("dstack-nvidia-0.5.12").unwrap(),
            format!("{RELEASES}/v0.5.12/dstack-nvidia-0.5.12.tar.gz")
        );
        assert!(release_url("dstack-nvidia").is_err());
        assert!(release_url("../x-0.5.12").is_err());
        assert!(release_url("dstack-0.5.12/../a").is_err());
    }

    #[test]
    fn keeps_only_the_five_files() {
        let mut files = all_kept("dstack-nvidia-0.5.12/");
        files.insert(
            0,
            (
                "dstack-nvidia-0.5.12/rootfs.img.verity".to_owned(),
                vec![7; 10],
            ),
        );
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        let out = scratch("keep");
        extract(archive(&refs).as_slice(), &out).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut want: Vec<String> = KEPT.iter().map(|k| (*k).to_owned()).collect();
        want.sort();
        assert_eq!(names, want);
        assert_eq!(std::fs::read(out.join("bzImage")).unwrap(), b"bzImage");
    }

    #[test]
    fn missing_or_doubled_files_fail() {
        let files = all_kept("");
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        assert!(extract(archive(&refs[1..]).as_slice(), &scratch("missing")).is_err());
        let doubled = [&refs[..1], &refs[..1]].concat();
        assert!(extract(archive(&doubled).as_slice(), &scratch("doubled")).is_err());
    }

    #[test]
    fn nested_files_fail() {
        let files = all_kept("a/b/");
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        assert!(extract(archive(&refs).as_slice(), &scratch("nested")).is_err());
    }
}
