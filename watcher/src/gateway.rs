use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::bundle::{self, Collateral, Gpu, MAX_AGE_SECS};
use crate::fetch;
use crate::image::Images;
use crate::report::Report;
use crate::review::{self, Role};
use crate::verdict::{Check, Status, Tier};

/// NEAR's gateway, which NEAR recommends to its users over the direct model hosts.
pub const HOST: &str = "cloud-api.near.ai";

/// Everything one gateway answer rests on, saved as fetched so the checks can be re-run offline.
#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub host: String,
    pub model: String,
    /// Unix seconds when the answer and its collateral were fetched; quotes are appraised at this time.
    pub fetched_at: u64,
    pub nonce: String,
    /// SHA-256 of the SubjectPublicKeyInfo of the certificate on the connection that returned the answer.
    pub peer_spki_sha256: String,
    /// The gateway's answer exactly as received.
    pub report: String,
    /// For the gateway machine's quote.
    pub collateral: Vec<Collateral>,
    /// For each entry of the answer's `model_attestations`, in order.
    pub candidates: Vec<Evidence>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub collateral: Vec<Collateral>,
    #[serde(default)]
    pub gpu: Option<Gpu>,
}

#[derive(Deserialize)]
struct Answer<'a> {
    #[serde(borrow)]
    gateway_attestation: &'a RawValue,
    #[serde(borrow, default)]
    model_attestations: Vec<&'a RawValue>,
}

impl<'a> Answer<'a> {
    fn parse(raw: &'a str) -> Result<Self> {
        serde_json::from_str(raw).context("not a gateway attestation answer")
    }
}

fn url(model: &str, nonce: &str) -> Result<String> {
    ensure!(
        !model.is_empty()
            && model
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._/".contains(c)),
        "model {model:?} may hold only letters, digits, '-', '.', '_' and '/'"
    );
    Ok(format!(
        "https://{HOST}/v1/attestation/report?model={model}&provider=near&signing_algo=ed25519&nonce={nonce}&include_tls_fingerprint=true"
    ))
}

/// Fetches the gateway's answer for `model` with our nonce, without an API key, then the collateral
/// for every quote in it and NRAS's verdict on each candidate's GPU evidence.
pub async fn fetch(model: &str) -> Result<Bundle> {
    let client = fetch::client()?;
    let nonce = fetch::new_nonce()?;
    let response = client
        .get(url(model, &nonce)?)
        .header(ACCEPT, "application/json")
        .header("x-no-aliasing", "true")
        .send()
        .await?
        .error_for_status()?;
    let (report, peer_spki_sha256) = fetch::body_and_peer(response).await?;
    let fetched_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let answer = Answer::parse(&report)?;
    let (collateral, _) =
        fetch::evidence(&client, &Report::parse(answer.gateway_attestation.get())?).await?;
    let mut candidates = Vec::with_capacity(answer.model_attestations.len());
    for raw in &answer.model_attestations {
        let (collateral, gpu) = fetch::evidence(&client, &Report::parse(raw.get())?).await?;
        candidates.push(Evidence { collateral, gpu });
    }
    Ok(Bundle {
        host: HOST.to_owned(),
        model: model.to_owned(),
        fetched_at,
        nonce,
        peer_spki_sha256,
        report,
        collateral,
        candidates,
    })
}

/// The candidates' reports in one gateway answer for `model`, without collateral or GPU evidence.
pub async fn candidates(model: &str) -> Result<Vec<Report>> {
    let response = fetch::client()?
        .get(url(model, &fetch::new_nonce()?)?)
        .header(ACCEPT, "application/json")
        .header("x-no-aliasing", "true")
        .send()
        .await?
        .error_for_status()?;
    let (report, _) = fetch::body_and_peer(response).await?;
    Answer::parse(&report)?
        .model_attestations
        .iter()
        .map(|raw| Report::parse(raw.get()))
        .collect()
}

impl Bundle {
    pub fn read(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// The dstack OS images the gateway and its candidates declare, as (name, os_image_hash).
    pub fn images(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let answer = Answer::parse(&self.report)?;
        std::iter::once(answer.gateway_attestation)
            .chain(answer.model_attestations)
            .map(|raw| {
                let vm = Report::parse(raw.get())?.vm_config()?;
                let name = vm.image.context("vm_config names no image")?;
                Ok((name, vm.os_image_hash))
            })
            .collect()
    }

    /// The gateway machine and each candidate as a machine bundle, with this answer's nonce and time.
    fn machines(self) -> Result<(bundle::Bundle, Vec<bundle::Bundle>)> {
        let answer = Answer::parse(&self.report)?;
        ensure!(
            answer.model_attestations.len() == self.candidates.len(),
            "{} candidates in the answer, evidence for {}",
            answer.model_attestations.len(),
            self.candidates.len()
        );
        let part = |raw: &RawValue, collateral, gpu| bundle::Bundle {
            host: self.host.clone(),
            fetched_at: self.fetched_at,
            nonce: self.nonce.clone(),
            peer_spki_sha256: self.peer_spki_sha256.clone(),
            report: raw.get().to_owned(),
            collateral,
            gpu,
            registry: None,
        };
        let candidates = answer
            .model_attestations
            .iter()
            .zip(self.candidates)
            .map(|(raw, e)| part(raw, e.collateral, e.gpu))
            .collect();
        Ok((
            part(answer.gateway_attestation, self.collateral, None),
            candidates,
        ))
    }
}

/// TLS keys of the machines serving `model` that a direct sweep reached within 24 hours of `at`.
pub fn direct_keys(bundles: &[bundle::Bundle], model: &str, at: u64) -> HashSet<String> {
    bundles
        .iter()
        .filter(|b| b.fetched_at.abs_diff(at) < MAX_AGE_SECS)
        .filter(|b| Report::parse(&b.report).is_ok_and(|r| r.model_name.as_deref() == Some(model)))
        .map(|b| b.peer_spki_sha256.to_ascii_lowercase())
        .collect()
}

fn reached_directly(report: &Report, direct: Option<&HashSet<String>>) -> Check {
    let (status, detail) = match (direct, report.tls_cert_fingerprint.as_deref()) {
        (None, _) => (
            Status::Unknown,
            "no direct sweep to compare with".to_owned(),
        ),
        (_, None) => (Status::Unknown, "the candidate binds no TLS key".to_owned()),
        (Some(keys), Some(fp)) if keys.contains(&fp.to_ascii_lowercase()) => (
            Status::Pass,
            format!("TLS key {fp} belongs to a machine reached directly"),
        ),
        (Some(keys), Some(fp)) => (
            Status::Unknown,
            format!(
                "TLS key {fp} is not among the {} machines reached directly within 24 hours",
                keys.len()
            ),
        ),
    };
    Check::new(5, "reached_directly", status, detail)
}

/// The report's `model_name` is the serving machine's own claim; the quote does not cover it.
fn model_requested(report: &Report, model: &str) -> Check {
    let (status, detail) = match report.model_name.as_deref() {
        Some(name) if name == model => (Status::Pass, format!("the candidate names {name}")),
        Some(name) => (
            Status::Fail,
            format!("the candidate names {name}, not the requested {model}"),
        ),
        None => (Status::Fail, "the candidate names no model".to_owned()),
    };
    Check::new(5, "model_requested", status, detail)
}

#[derive(Debug, Serialize)]
pub struct Review {
    pub watcher: &'static str,
    pub host: String,
    pub model: String,
    pub fetched_at: u64,
    pub nonce: String,
    /// The key of the client's connection to the gateway.
    pub peer_spki_sha256: String,
    pub tier: Tier,
    /// Checks on the route as a whole, beyond any one machine.
    pub route: Vec<Check>,
    pub gateway: review::Review,
    pub candidates: Vec<review::Review>,
}

fn route_checks(candidates: usize) -> Vec<Check> {
    let present = match candidates {
        0 => Check::new(
            12,
            "candidates",
            Status::Unknown,
            "the answer has no model evidence",
        ),
        n => Check::new(
            12,
            "candidates",
            Status::Pass,
            format!("{n} candidate machine(s)"),
        ),
    };
    vec![
        present,
        Check::new(
            12,
            "forwarding_observable",
            Status::Warn,
            "a client cannot see which machine the gateway forwards a request to; the candidates \
             are not an inventory of those machines",
        ),
    ]
}

/// The worst of the gateway's and the candidates' tiers, never above `warning`, and no
/// verdict without a candidate.
fn route_tier(gateway: Tier, candidates: &[Tier]) -> Tier {
    let empty = candidates.is_empty().then_some(Tier::None);
    let worst = Tier::worst(
        std::iter::once(gateway)
            .chain(candidates.iter().copied())
            .chain(empty),
    );
    match worst {
        Tier::Affirming => Tier::Warning,
        other => other,
    }
}

/// Reviews the gateway machine and each candidate; `direct` holds the bundles of a direct sweep
/// of the same model. Deterministic: the same inputs give the same review.
pub fn review(
    bundle: Bundle,
    direct: Option<&[bundle::Bundle]>,
    images: &Images,
) -> Result<Review> {
    let (host, model, fetched_at) = (bundle.host.clone(), bundle.model.clone(), bundle.fetched_at);
    let (nonce, peer_spki_sha256) = (bundle.nonce.clone(), bundle.peer_spki_sha256.clone());
    let keys = direct.map(|d| direct_keys(d, &model, fetched_at));
    let (gateway, candidates) = bundle.machines()?;
    let gateway = review::machine(&gateway, images, Role::Gateway, Vec::new())?;
    let candidates = candidates
        .iter()
        .map(|c| {
            let report = Report::parse(&c.report)?;
            let extra = vec![
                model_requested(&report, &model),
                reached_directly(&report, keys.as_ref()),
            ];
            review::machine(c, images, Role::Candidate, extra)
        })
        .collect::<Result<Vec<_>>>()?;
    let tiers: Vec<Tier> = candidates.iter().map(|c| c.tier).collect();
    Ok(Review {
        watcher: concat!("sealed-review-watcher/", env!("CARGO_PKG_VERSION")),
        host,
        model,
        fetched_at,
        nonce,
        peer_spki_sha256,
        tier: route_tier(gateway.tier, &tiers),
        route: route_checks(candidates.len()),
        gateway,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: &str = "z-ai/glm-5.3-flash";

    fn report(model: Option<&str>, fingerprint: Option<&str>) -> Report {
        let mut value = serde_json::json!({
            "signing_address": "0x01",
            "signing_algo": "ecdsa",
            "request_nonce": "00",
            "intel_quote": "",
            "info": {
                "app_id": "a", "instance_id": "i", "app_name": "n", "vm_config": "{}",
                "tcb_info": { "app_compose": "{}", "event_log": [] },
            },
        });
        if let Some(m) = model {
            value["model_name"] = m.into();
        }
        if let Some(fp) = fingerprint {
            value["tls_cert_fingerprint"] = fp.into();
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn route_is_at_most_warning() {
        use Tier::*;
        assert_eq!(route_tier(Affirming, &[Affirming, Affirming]), Warning);
        assert_eq!(route_tier(Warning, &[Affirming]), Warning);
        assert_eq!(route_tier(Affirming, &[None, Affirming]), None);
        assert_eq!(route_tier(Contraindicated, &[None]), Contraindicated);
        assert_eq!(route_tier(Affirming, &[]), None);
    }

    #[test]
    fn candidate_must_be_reached_directly() {
        let keys: HashSet<String> = ["ab".to_owned()].into();
        let status = |fp, keys| reached_directly(&report(Some(MODEL), fp), keys).status;
        assert_eq!(status(Some("AB"), Some(&keys)), Status::Pass);
        assert_eq!(status(Some("cd"), Some(&keys)), Status::Unknown);
        assert_eq!(status(None, Some(&keys)), Status::Unknown);
        assert_eq!(status(Some("ab"), None), Status::Unknown);
    }

    #[test]
    fn candidate_must_serve_the_requested_model() {
        let status = |m| model_requested(&report(m, None), MODEL).status;
        assert_eq!(status(Some(MODEL)), Status::Pass);
        assert_eq!(status(Some("org/other")), Status::Fail);
        assert_eq!(status(None), Status::Fail);
    }

    #[test]
    fn direct_keys_are_recent_and_of_the_model() {
        let at = 1_800_000_000;
        let with_model = |instance, tls, fetched_at, model: &str| {
            let mut b = bundle::sample(instance, tls, fetched_at);
            let mut r: serde_json::Value = serde_json::from_str(&b.report).unwrap();
            r["model_name"] = model.into();
            b.report = r.to_string();
            b
        };
        let bundles = [
            with_model("a", "AA", at - 60, MODEL),
            with_model("b", "bb", at - MAX_AGE_SECS, MODEL),
            with_model("c", "cc", at, "org/other"),
        ];
        assert_eq!(direct_keys(&bundles, MODEL, at), ["aa".to_owned()].into());
    }

    #[test]
    fn model_name_is_checked_before_it_reaches_the_url() {
        assert!(url(MODEL, "00").is_ok());
        assert!(url("a&nonce=00", "00").is_err());
        assert!(url("", "00").is_err());
    }
}
