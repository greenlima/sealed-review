use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod attributes;
mod binding;
mod bundle;
mod compose;
mod diff;
mod e2ee;
mod events;
mod feed;
mod fetch;
mod gate;
mod gateway;
mod gpu;
mod image;
mod kms;
mod launcher;
mod measure;
mod mirror;
mod ohttp;
mod quote;
mod registry;
mod report;
mod review;
mod verdict;

#[derive(Parser)]
#[command(
    version,
    about = "Checks a NEAR AI model endpoint's attestation, link by link"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch reports with fresh nonces until no new machine appears, and save one bundle per machine
    Fetch {
        #[arg(long, default_value = "glm-5-3-flash.completions.near.ai")]
        host: String,
        /// Directory for `sweep.json` and one `machine-N.json` bundle per machine; machines of earlier sweeps stay for 24 hours
        #[arg(long)]
        out: PathBuf,
        /// Most report fetches to make
        #[arg(long, default_value_t = 12)]
        tries: u32,
        /// Stop after this many fetches in a row reach no new machine
        #[arg(long, default_value_t = 4)]
        quiet: u32,
    },
    /// Fetch the dstack OS image a bundle declares into the cache, checked against its hash
    Image {
        bundle: PathBuf,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Check a saved bundle offline and print the review as JSON
    Check {
        bundle: PathBuf,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Check two saved bundles of one endpoint offline and print what changed as JSON
    Diff {
        old: PathBuf,
        new: PathBuf,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Review every machine of a fetch directory and write the next feed entry, unsigned
    Draft {
        sweep: PathBuf,
        #[command(flatten)]
        feed: FeedArgs,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Write an unsigned entry that corrects an earlier one
    Correct {
        seq: u64,
        #[arg(long, value_parser = parse_tier)]
        status: verdict::Tier,
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        feed: FeedArgs,
    },
    /// Write an unsigned entry that retires a feed key, for another key to sign
    Retire {
        /// The key id to retire, as `watcher verify` lists it
        kid: String,
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        feed: FeedArgs,
    },
    /// Join a draft and its YubiKey signature into the next feed entry, after checking both
    Seal {
        draft: PathBuf,
        signature: PathBuf,
        #[command(flatten)]
        feed: FeedArgs,
    },
    /// Verify every feed entry and print the current verdict per host as JSON
    Verify {
        #[command(flatten)]
        feed: FeedArgs,
    },
    /// Compare the feed with its NEAR testnet mirror, read from two RPC providers
    Mirror {
        /// The mirror contract's account, e.g. `<name>.testnet`
        #[arg(long)]
        contract: String,
        #[command(flatten)]
        feed: FeedArgs,
    },
    /// Read the feed from its mirror and say whether a request to the host may be sent, and to which machines
    Gate {
        #[command(flatten)]
        gate: GateArgs,
    },
    /// Send one chat request through the gate, only to a machine the current verdict reviewed (reads NEARAI_API_KEY)
    Ask {
        #[command(flatten)]
        gate: GateArgs,
        #[arg(long, default_value = "z-ai/glm-5.3-flash")]
        model: String,
        #[arg(long)]
        prompt: String,
    },
    /// NEAR's gateway (cloud-api.near.ai): fetch its answer for a model, its images, or check it offline
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
}

#[derive(Subcommand)]
enum GatewayCommand {
    /// Fetch the gateway's attestation answer with a fresh nonce, no API key, and the evidence it needs
    Fetch {
        #[arg(long, default_value = "z-ai/glm-5.3-flash")]
        model: String,
        /// File for the gateway bundle
        #[arg(long)]
        out: PathBuf,
    },
    /// Fetch the dstack OS images the gateway and its candidates declare into the cache
    Image {
        bundle: PathBuf,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Check a saved gateway bundle offline and print the review as JSON
    Check {
        bundle: PathBuf,
        /// Fetch directory of a direct sweep of the same model; without it no candidate counts as reached directly
        #[arg(long)]
        direct: Option<PathBuf>,
        #[command(flatten)]
        images: ImageArgs,
    },
    /// Review a saved gateway bundle and write the next feed entry for its route, unsigned
    Draft {
        bundle: PathBuf,
        /// Fetch directory of a direct sweep of the same model
        #[arg(long)]
        direct: PathBuf,
        #[command(flatten)]
        feed: FeedArgs,
        #[command(flatten)]
        images: ImageArgs,
    },
}

#[derive(clap::Args)]
struct GateArgs {
    /// A direct host, or `cloud-api.near.ai/<model id>` for the route through NEAR's gateway
    #[arg(long, default_value = "glm-5-3-flash.completions.near.ai")]
    host: String,
    /// The mirror contract's account, e.g. `<name>.testnet`
    #[arg(long)]
    contract: String,
    /// The feed's P-256 public keys (PEM), one `--key` each
    #[arg(long = "key", required = true)]
    keys: Vec<PathBuf>,
    /// Also let `warning` verdicts through
    #[arg(long, value_parser = ["warning"])]
    accept: Option<String>,
}

impl GateArgs {
    async fn admit(&self) -> Result<gate::Admission> {
        let keys = feed::Keys::read(&self.keys)?;
        let policy = gate::Policy {
            accept_warning: self.accept.is_some(),
        };
        gate::gate(&self.host, &self.contract, keys, policy, now()?).await
    }
}

#[derive(clap::Args)]
struct ImageArgs {
    /// Extracted dstack OS image (ovmf.fd, bzImage, initramfs.cpio.gz, metadata.json, sha256sum.txt);
    /// overrides the cache
    #[arg(long)]
    image_dir: Option<PathBuf>,
    /// Image cache, one directory per os_image_hash [default: ~/.cache/sealed-review/images]
    #[arg(long)]
    cache: Option<PathBuf>,
}

impl ImageArgs {
    fn cache(&self) -> Result<PathBuf> {
        self.cache.clone().map_or_else(image::default_cache, Ok)
    }

    fn images(&self) -> Result<image::Images> {
        Ok(match &self.image_dir {
            Some(dir) => image::Images::Dir(dir.clone()),
            None => image::Images::Cache(self.cache()?),
        })
    }
}

#[derive(clap::Args)]
struct FeedArgs {
    /// Feed directory: `000001.jwt`, `000002.jwt`, …
    #[arg(long)]
    feed: PathBuf,
    /// The feed's P-256 public keys (PEM), one `--key` each, as each YubiKey exported its key;
    /// the first one not retired signs new drafts
    #[arg(long = "key", required = true)]
    keys: Vec<PathBuf>,
}

impl FeedArgs {
    fn open(&self) -> Result<feed::Feed> {
        feed::Feed::open(&self.feed, feed::Keys::read(&self.keys)?)
    }
}

fn parse_tier(text: &str) -> Result<verdict::Tier> {
    serde_json::from_value(text.into()).context("affirming, warning, contraindicated or none")
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn reviewed(path: &Path, images: &image::Images) -> Result<(bundle::Bundle, review::Review)> {
    let bundle = bundle::Bundle::read(path)?;
    let review = review::review(&bundle, images)?;
    Ok((bundle, review))
}

fn problems(bundle: &bundle::Bundle) -> String {
    let mut problems: Vec<String> = bundle
        .collateral
        .iter()
        .filter_map(|c| {
            let error = c.error.as_ref()?;
            Some(format!("collateral {:?}/{:?}: {error}", c.source, c.stream))
        })
        .collect();
    if let Some(error) = bundle.gpu.as_ref().and_then(|g| g.error.as_ref()) {
        problems.push(format!("nras: {error}"));
    }
    if problems.is_empty() {
        "ok".into()
    } else {
        problems.join("; ")
    }
}

fn drafted(drafted: &feed::Drafted) {
    let path = &drafted.path;
    let sig = path.with_extension("sig");
    eprintln!("draft {}", path.display());
    eprintln!(
        "sign it on the YubiKey holding key {}: yubico-piv-tool -a verify-pin --sign -s 9c -A ECCP256 -H SHA256 -i {} -o {}",
        drafted.kid,
        path.display(),
        sig.display()
    );
    eprintln!(
        "then: watcher seal {} {} --feed <dir> --key <pem> --key <pem>",
        path.display(),
        sig.display()
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fetch {
            host,
            out,
            tries,
            quiet,
        } => {
            let at = now()?;
            let (made, bundles) = fetch::sweep(&host, fetch::Coverage::new(tries, quiet)).await?;
            for b in &bundles {
                eprintln!("{}: {}", b.peer_spki_sha256, problems(b));
            }
            let run = bundle::Run { at, tries: made };
            let merged = bundle::Sweep::merge(&out, &host, run, &bundles, now()?)?;
            let plan = &merged.plan;
            eprintln!(
                "{} machine(s) in {made} fetch(es): {} new, {} seen again; {} kept from earlier sweeps, {} dropped (24 h old); {} machine(s) in {}",
                bundles.len(),
                plan.add.len(),
                plan.replace.len(),
                plan.keep.len(),
                plan.drop.len(),
                merged.sweep.bundles.len(),
                out.display()
            );
        }
        Command::Image { bundle, images } => {
            let bundle = bundle::Bundle::read(&bundle)?;
            let vm = report::Report::parse(&bundle.report)?.vm_config()?;
            let name = vm.image.context("vm_config names no image")?;
            let dir = image::fetch(&name, &vm.os_image_hash, &images.cache()?).await?;
            eprintln!("{name}: {}", dir.display());
        }
        Command::Check { bundle, images } => {
            let (_, review) = reviewed(&bundle, &images.images()?)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Command::Diff { old, new, images } => {
            let images = images.images()?;
            let (old_bundle, old_review) = reviewed(&old, &images)?;
            let (new_bundle, new_review) = reviewed(&new, &images)?;
            let diff = diff::diff((&old_bundle, &old_review), (&new_bundle, &new_review))?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        Command::Draft {
            sweep,
            feed,
            images,
        } => {
            let feed = feed.open()?;
            let images = images.images()?;
            let now = now()?;
            let (sweep, bundles) = bundle::Sweep::read(&sweep)?;
            let (fresh, stale): (Vec<_>, Vec<_>) = bundles.into_iter().partition(|b| b.fresh(now));
            if !stale.is_empty() {
                eprintln!(
                    "left out {} machine(s) fetched 24 hours ago or earlier",
                    stale.len()
                );
            }
            let reviewed = fresh
                .into_iter()
                .map(|b| {
                    let review = review::review(&b, &images)?;
                    Ok((b, review))
                })
                .collect::<Result<Vec<_>>>()?;
            let claims = feed.verdict(&sweep, &reviewed, now)?;
            eprintln!("status {}", claims["ear_status"]);
            drafted(&feed.write_draft(&claims)?);
        }
        Command::Correct {
            seq,
            status,
            reason,
            feed,
        } => {
            let feed = feed.open()?;
            let claims = feed.correction(seq, status, &reason, now()?)?;
            drafted(&feed.write_draft(&claims)?);
        }
        Command::Retire { kid, reason, feed } => {
            let feed = feed.open()?;
            let claims = feed.retirement(&kid, &reason, now()?)?;
            drafted(&feed.write_draft(&claims)?);
        }
        Command::Seal {
            draft,
            signature,
            feed,
        } => {
            let entry = feed.open()?.seal(&draft, &signature)?;
            eprintln!("entry {}", entry.display());
        }
        Command::Verify { feed } => {
            let feed = feed.open()?;
            println!("{}", serde_json::to_string_pretty(&feed.summary(now()?))?);
        }
        Command::Mirror { contract, feed } => {
            let feed = feed.open()?;
            let report = mirror::check(&contract, feed.kids(), &feed.hashes()).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if let Some(mirror::Standing::Behind { missing }) = &report.standing {
                for seq in missing {
                    appendable(&contract, &feed.entry_file(*seq)?);
                }
            }
            anyhow::ensure!(
                report.ok,
                "the mirror does not confirm this feed (see agree, locked, same_keys, standing)"
            );
        }
        Command::Gate { gate } => {
            let admission = gate.admit().await?;
            println!("{}", serde_json::to_string_pretty(&admission)?);
        }
        Command::Ask {
            gate,
            model,
            prompt,
        } => {
            let (connect, routed) = gate::connect(&gate.host);
            if let Some(routed) = routed {
                anyhow::ensure!(
                    routed == model,
                    "the verdict for {} covers {routed}, not {model}",
                    gate.host
                );
            }
            let api_key = std::env::var("NEARAI_API_KEY")
                .context("set NEARAI_API_KEY to your NEAR AI API key")?;
            let admission = gate.admit().await?;
            eprintln!(
                "gate passed: entry {} ({}), {} reviewed machine(s)",
                admission.pass.seq,
                serde_json::to_value(admission.pass.status)?,
                admission.pass.tls_keys.len()
            );
            let sealed = routed
                .map(|_| {
                    let key = admission
                        .pass
                        .model_keys
                        .first()
                        .context("the gate passed no model key")?;
                    e2ee::Client::new(key)
                })
                .transpose()?;
            let content = match &sealed {
                Some(client) => client.seal(&prompt)?,
                None => prompt,
            };
            let request = serde_json::json!({
                "model": model,
                "messages": [{ "role": "user", "content": content }],
                "stream": false,
            });
            let mut answer = gate::ask(
                &format!("https://{connect}"),
                gate::system_roots()?,
                &admission.pass.tls_keys,
                &api_key,
                &sealed
                    .as_ref()
                    .map(e2ee::Client::headers)
                    .unwrap_or_default(),
                &request,
            )
            .await?;
            eprintln!("answered on the connection with TLS key {}", answer.tls_key);
            if let Some(client) = &sealed {
                client.open_answer(&mut answer.response)?;
                eprintln!(
                    "end-to-end encrypted to model key {}",
                    &client.model_key()[..16]
                );
            }
            let content = &answer.response["choices"][0]["message"]["content"];
            match content.as_str() {
                Some(text) => println!("{text}"),
                None => println!("{}", serde_json::to_string_pretty(&answer.response)?),
            }
        }
        Command::Gateway { command } => gateway_command(command).await?,
    }
    Ok(())
}

async fn gateway_command(command: GatewayCommand) -> Result<()> {
    match command {
        GatewayCommand::Fetch { model, out } => {
            let bundle = gateway::fetch(&model).await?;
            bundle.write(&out)?;
            eprintln!(
                "{}: {} candidate machine(s); saved {}",
                bundle.peer_spki_sha256,
                bundle.candidates.len(),
                out.display()
            );
        }
        GatewayCommand::Image { bundle, images } => {
            let cache = images.cache()?;
            for (name, hash) in gateway::Bundle::read(&bundle)?.images()? {
                let dir = image::fetch(&name, &hash, &cache).await?;
                eprintln!("{name}: {}", dir.display());
            }
        }
        GatewayCommand::Check {
            bundle,
            direct,
            images,
        } => {
            let review = gateway_reviewed(&bundle, direct.as_deref(), &images)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        GatewayCommand::Draft {
            bundle,
            direct,
            feed,
            images,
        } => {
            let feed = feed.open()?;
            let review = gateway_reviewed(&bundle, Some(&direct), &images)?;
            let claims = feed.gateway_verdict(&review, now()?)?;
            eprintln!(
                "{}: status {}",
                claims["sr_scope"]["host"], claims["ear_status"]
            );
            drafted(&feed.write_draft(&claims)?);
        }
    }
    Ok(())
}

fn gateway_reviewed(
    bundle: &Path,
    direct: Option<&Path>,
    images: &ImageArgs,
) -> Result<gateway::Review> {
    let direct = direct
        .map(|dir| bundle::Sweep::read(dir).map(|(_, bundles)| bundles))
        .transpose()?;
    gateway::review(
        gateway::Bundle::read(bundle)?,
        direct.as_deref(),
        &images.images()?,
    )
}

fn appendable(contract: &str, entry: &Path) {
    eprintln!(
        "append with your NEAR account: near contract call-function as-transaction {contract} append json-args \"$(jq -Rc '{{jws: .}}' {})\" prepaid-gas '100 Tgas' attached-deposit '0.1 NEAR' sign-as <relay>.testnet network-config testnet sign-with-legacy-keychain send",
        entry.display()
    );
}
