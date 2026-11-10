use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use dcap_qvl::collateral::{CollateralClient, INTEL_PCS_URL, PHALA_PCCS_URL, TcbEvaluationDataSet};
use der::{Decode, Encode};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::tls::TlsInfo;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::bundle::{Bundle, Collateral, Gpu, Jwk, Machine, Source, Stream, machine};
use crate::gpu::signing_kids;
use crate::registry;
use crate::report::Report;

const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
pub const USER_AGENT: &str = concat!("sealed-review-watcher/", env!("CARGO_PKG_VERSION"));
const NRAS_GPU: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const NRAS_JWKS: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
const COLLATERAL: [(Source, Stream); 3] = [
    (Source::Intel, Stream::Standard),
    (Source::Intel, Stream::Early),
    (Source::Phala, Stream::Standard),
];

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// When a sweep stops: after `max` fetches, or after `quiet` fetches in a row that found no new machine.
pub struct Coverage {
    max: u32,
    quiet: u32,
    tries: u32,
    unchanged: u32,
    seen: HashSet<Machine>,
}

impl Coverage {
    pub fn new(max: u32, quiet: u32) -> Self {
        Self {
            max,
            quiet,
            tries: 0,
            unchanged: 0,
            seen: HashSet::new(),
        }
    }

    /// Records one fetch; true when it reached a machine not seen before.
    fn observe(&mut self, machine: Machine) -> bool {
        self.tries += 1;
        let new = self.seen.insert(machine);
        self.unchanged = if new { 0 } else { self.unchanged + 1 };
        new
    }

    fn done(&self) -> bool {
        self.tries >= self.max || self.unchanged >= self.quiet
    }
}

/// One report with our own nonce, before its collateral and GPU appraisal are fetched.
struct Observed {
    nonce: String,
    fetched_at: u64,
    peer_spki_sha256: String,
    report: String,
    parsed: Report,
}

impl Observed {
    fn machine(&self) -> Machine {
        machine(&self.parsed, &self.peer_spki_sha256)
    }
}

/// Fetches NEAR's registry once, then reports until `coverage` stops, and completes a bundle for
/// each machine reached. No connection is reused: a load balancer keeps a kept-alive connection on
/// one machine.
pub async fn sweep(host: &str, mut coverage: Coverage) -> Result<(u32, Vec<Bundle>)> {
    let client = client()?;
    let registry = registry::fetch(&client)
        .await
        .inspect_err(|e| eprintln!("registry: {e:#}; its check will be unknown"))
        .ok();
    let mut bundles = Vec::new();
    while !coverage.done() {
        let observed = observe(&client, host).await?;
        if coverage.observe(observed.machine()) {
            bundles.push(complete(&client, host, observed, registry.clone()).await?);
        }
    }
    Ok((coverage.tries, bundles))
}

/// Reports alone, until `coverage` stops: one per machine reached, without collateral or GPU evidence.
pub async fn reports(host: &str, mut coverage: Coverage) -> Result<Vec<Report>> {
    let client = client()?;
    let mut reports = Vec::new();
    while !coverage.done() {
        let observed = observe(&client, host).await?;
        if coverage.observe(observed.machine()) {
            reports.push(observed.parsed);
        }
    }
    Ok(reports)
}

async fn observe(client: &reqwest::Client, host: &str) -> Result<Observed> {
    let nonce = new_nonce()?;
    let (report, peer_spki_sha256) = report(client, host, &nonce).await?;
    let fetched_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let parsed = Report::parse(&report)?;
    Ok(Observed {
        nonce,
        fetched_at,
        peer_spki_sha256,
        report,
        parsed,
    })
}

/// Adds the collateral for the report's quote from each source and NRAS's verdict on its GPU evidence.
async fn complete(
    client: &reqwest::Client,
    host: &str,
    observed: Observed,
    registry: Option<String>,
) -> Result<Bundle> {
    let (collateral, gpu) = evidence(client, &observed.parsed).await?;
    Ok(Bundle {
        host: host.to_owned(),
        fetched_at: observed.fetched_at,
        nonce: observed.nonce,
        peer_spki_sha256: observed.peer_spki_sha256,
        report: observed.report,
        collateral,
        gpu,
        registry,
    })
}

/// Our TLS-pinning-ready client: HTTPS only, the peer certificate kept, no connection reused.
pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .tls_info(true)
        .timeout(Duration::from_secs(120))
        .user_agent(USER_AGENT)
        .pool_max_idle_per_host(0)
        .build()?)
}

/// The collateral for a report's quote from each source, and NRAS's verdict on its GPU evidence.
pub async fn evidence(
    client: &reqwest::Client,
    report: &Report,
) -> Result<(Vec<Collateral>, Option<Gpu>)> {
    let quote = hex::decode(&report.intel_quote).context("intel_quote is not hex")?;
    let mut collateral = Vec::with_capacity(COLLATERAL.len());
    for (source, stream) in COLLATERAL {
        collateral.push(fetch_collateral(&quote, source, stream).await);
    }
    let gpu = match report.nvidia_payload.as_deref() {
        Some(payload) => Some(gpu(client, payload).await),
        None => None,
    };
    Ok((collateral, gpu))
}

pub fn new_nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(hex::encode(bytes))
}

pub async fn capped(response: reqwest::Response) -> Result<String> {
    let body = response.bytes().await?;
    if body.len() > MAX_BODY_BYTES {
        bail!("response larger than {MAX_BODY_BYTES} bytes");
    }
    Ok(String::from_utf8(body.to_vec())?)
}

async fn report(client: &reqwest::Client, host: &str, nonce: &str) -> Result<(String, String)> {
    let url = format!(
        "https://{host}/v1/attestation/report?signing_algo=ed25519&nonce={nonce}&include_tls_fingerprint=true"
    );
    body_and_peer(client.get(url).send().await?.error_for_status()?).await
}

/// The body and the SHA-256 of the SPKI of the certificate on the connection that returned it.
pub async fn body_and_peer(response: reqwest::Response) -> Result<(String, String)> {
    let peer = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .context("no peer certificate on the report's connection")?;
    let spki = spki_sha256(peer)?;
    Ok((capped(response).await?, spki))
}

pub fn spki_sha256(cert_der: &[u8]) -> Result<String> {
    let cert = Certificate::from_der(cert_der)?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
    Ok(hex::encode(Sha256::digest(spki)))
}

async fn fetch_collateral(quote: &[u8], source: Source, stream: Stream) -> Collateral {
    let url = match source {
        Source::Intel => INTEL_PCS_URL,
        Source::Phala => PHALA_PCCS_URL,
    };
    let set = match stream {
        Stream::Standard => TcbEvaluationDataSet::Standard,
        Stream::Early => TcbEvaluationDataSet::Early,
    };
    let fetched = match CollateralClient::with_default_http(url) {
        Ok(client) => client.with_evaluation_data_set(set).fetch(quote).await,
        Err(e) => Err(e),
    };
    match fetched {
        Ok(data) => Collateral {
            source,
            stream,
            data: Some(data),
            error: None,
        },
        Err(e) => Collateral {
            source,
            stream,
            data: None,
            error: Some(format!("{e:#}")),
        },
    }
}

async fn gpu(client: &reqwest::Client, payload: &str) -> Gpu {
    nras(client, payload).await.unwrap_or_else(|e| Gpu {
        error: Some(format!("{e:#}")),
        ..Gpu::default()
    })
}

/// Posts the GPU evidence unchanged, then keeps the JWKS entries the answer is signed with.
async fn nras(client: &reqwest::Client, payload: &str) -> Result<Gpu> {
    let answer = client
        .post(NRAS_GPU)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(payload.to_owned())
        .send()
        .await?
        .error_for_status()?;
    let response = capped(answer).await?;
    let kids = signing_kids(&response);
    let jwks: Jwks = serde_json::from_str(
        &capped(client.get(NRAS_JWKS).send().await?.error_for_status()?).await?,
    )?;
    let keys = jwks
        .keys
        .into_iter()
        .filter(|k| kids.contains(&k.kid))
        .collect();
    Ok(Gpu {
        response: Some(response),
        keys,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(instance: &str, tls: &str) -> Machine {
        (instance.into(), "compose".into(), tls.into())
    }

    /// Feeds machines until the coverage stops; returns how many were new.
    fn run(mut coverage: Coverage, machines: impl IntoIterator<Item = Machine>) -> (u32, usize) {
        let mut new = 0;
        for m in machines {
            if coverage.done() {
                break;
            }
            new += usize::from(coverage.observe(m));
        }
        (coverage.tries, new)
    }

    #[test]
    fn stops_after_quiet_repeats() {
        let seq = ["a", "b", "a", "b", "a", "b", "c"].map(|i| machine(i, "k"));
        assert_eq!(run(Coverage::new(12, 4), seq), (6, 2));
    }

    #[test]
    fn a_new_machine_resets_the_count() {
        let seq = ["a", "a", "a", "b", "a", "a", "a", "a"].map(|i| machine(i, "k"));
        assert_eq!(run(Coverage::new(12, 4), seq), (8, 2));
    }

    #[test]
    fn stops_at_max() {
        let seq = (0..20).map(|i| machine(&i.to_string(), "k"));
        assert_eq!(run(Coverage::new(12, 4), seq), (12, 12));
    }

    #[test]
    fn other_tls_key_is_another_machine() {
        let seq = [machine("a", "k1"), machine("a", "k2")];
        assert_eq!(run(Coverage::new(12, 4), seq), (2, 2));
    }
}
