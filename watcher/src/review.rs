use anyhow::{Context, Result};
use dcap_qvl::quote::TDReport10;
use dstack_types::VmConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::bundle::{Bundle, Source, Stream};
use crate::image::Images;
use crate::launcher::Workload;
use crate::ohttp::{self, KeyConfig};
use crate::report::Report;
use crate::verdict::{self, Check, Status, Tier, tier};
use crate::{attributes, binding, compose, events, gpu, kms, launcher, measure, quote, registry};

const QUOTE_DEPENDENT: [(u8, &str); 9] = [
    (3, "td_attributes"),
    (3, "xfam"),
    (3, "os_image"),
    (3, "measurements"),
    (3, "rtmr_replay"),
    (5, "rtmr3_events"),
    (4, "nonce_fresh"),
    (4, "signer_bound"),
    (5, "config_measured"),
];

/// What a machine is to the client, which decides the checks it gets and the ones it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A model machine the client connects to.
    Direct,
    /// NEAR's gateway machine, which the client connects to instead.
    Gateway,
    /// A model machine behind the gateway, seen only through the gateway's answer.
    Candidate,
}

impl Role {
    fn required(self) -> &'static [&'static str] {
        match self {
            Role::Direct => &verdict::DIRECT,
            Role::Gateway => &verdict::GATEWAY,
            Role::Candidate => &verdict::CANDIDATE,
        }
    }

    fn connected(self) -> bool {
        self != Role::Candidate
    }

    fn serves_models(self) -> bool {
        self != Role::Gateway
    }
}

#[derive(Debug, Serialize)]
pub struct Review {
    pub watcher: &'static str,
    pub host: String,
    pub fetched_at: u64,
    pub tier: Tier,
    pub facts: Facts,
    pub checks: Vec<Check>,
}

/// What the release is, as read from the report; trusted only as far as the checks pass.
#[derive(Debug, Serialize)]
pub struct Facts {
    pub app_id: String,
    pub instance_id: String,
    pub app_name: String,
    pub image: Option<String>,
    pub os_image_hash: String,
    pub compose_hash: String,
    pub signing_key: String,
    /// The TLS key the report binds, as SHA-256 of its SPKI.
    pub tls_key: Option<String>,
    pub mrtd: Option<String>,
    pub rtmr: Option<[String; 4]>,
    pub ohttp: Option<KeyConfig>,
    pub kms: Option<kms::Provider>,
    /// Empty: the compose accepts any key service.
    pub key_provider_id: Option<String>,
    /// What the launcher runs, as its log leaves it; absent on a machine without a launcher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<Workload>,
}

fn facts(report: &Report, vm: &VmConfig, td: Option<&TDReport10>) -> Facts {
    let tcb = &report.info.tcb_info;
    Facts {
        app_id: report.info.app_id.clone(),
        instance_id: report.info.instance_id.clone(),
        app_name: report.info.app_name.clone(),
        image: vm.image.clone(),
        os_image_hash: hex::encode(&vm.os_image_hash),
        compose_hash: hex::encode(Sha256::digest(tcb.app_compose.as_bytes())),
        signing_key: format!("{}:{}", report.signing_algo, report.signing_address),
        tls_key: report
            .tls_cert_fingerprint
            .as_deref()
            .map(str::to_ascii_lowercase),
        mrtd: td.map(|t| hex::encode(t.mr_td)),
        rtmr: td.map(|t| [t.rt_mr0, t.rt_mr1, t.rt_mr2, t.rt_mr3].map(hex::encode)),
        ohttp: ohttp::key(report),
        kms: kms::measured(&tcb.event_log),
        key_provider_id: kms::pinned(&tcb.app_compose),
        workload: report
            .compose_manager_attestation
            .as_ref()
            .map(|m| launcher::workload(&m.actions)),
    }
}

/// Runs every check on one bundle of a machine reached directly. Deterministic: the same bundle
/// and image give the same review.
pub fn review(bundle: &Bundle, images: &Images) -> Result<Review> {
    machine(bundle, images, Role::Direct, Vec::new())
}

/// Reviews one machine in its `role`; `extra` holds checks only the caller can make.
pub fn machine(bundle: &Bundle, images: &Images, role: Role, extra: Vec<Check>) -> Result<Review> {
    let report =
        Report::parse(&bundle.report).context("report is not a NEAR attestation report")?;
    let quote_bytes = hex::decode(&report.intel_quote).context("intel_quote is not hex")?;
    let vm = report.vm_config()?;

    let (mut checks, appraisal) = quote::checks(bundle, &quote_bytes);
    let td = appraisal.as_ref().map(|a| a.td);

    match &td {
        Some(td) => {
            checks.extend(attributes::checks(td, &hex::encode(&vm.os_image_hash)));
            checks.extend(binding::checks(&report, td, &bundle.nonce));
            if role.connected() {
                checks.push(binding::tls(&report, &bundle.peer_spki_sha256));
            }
            checks.extend(events::checks(
                &report.info.tcb_info.event_log,
                td,
                &report.info.tcb_info.app_compose,
                &vm.os_image_hash,
            ));
            let image_dir = images.dir_for(&vm.os_image_hash);
            checks.extend(measure::checks(image_dir.as_deref(), &vm, td));
            if role.serves_models() {
                let collateral = bundle
                    .collateral(Source::Intel, Stream::Standard)
                    .and_then(|c| c.data.as_ref());
                checks.push(launcher::check(
                    report.compose_manager_attestation.as_ref(),
                    td,
                    collateral,
                    &bundle.nonce,
                    bundle.fetched_at,
                ));
            }
        }
        None => {
            checks.extend(
                QUOTE_DEPENDENT
                    .map(|(link, id)| Check::new(link, id, Status::Unknown, "quote not verified")),
            );
            if role.connected() {
                checks.push(Check::new(
                    4,
                    "tls_bound",
                    Status::Unknown,
                    "quote not verified",
                ));
            }
            if role.serves_models() {
                checks.push(Check::new(
                    7,
                    "launcher_log_bound",
                    Status::Unknown,
                    "quote not verified",
                ));
            }
        }
    }
    if role == Role::Direct {
        checks.push(registry::check(
            bundle.registry.as_deref(),
            &bundle.host,
            report.model_name.as_deref(),
        ));
    }
    checks.extend(ohttp::check(&report));
    if role.serves_models() {
        checks.extend(gpu::checks(
            bundle.gpu.as_ref(),
            report.nvidia_payload.as_deref(),
            &bundle.nonce,
            bundle.fetched_at,
            vm.num_gpus,
            vm.num_nvswitches,
        ));
    } else {
        checks.push(gpu::absent(
            report.nvidia_payload.as_deref(),
            vm.num_gpus,
            vm.num_nvswitches,
        ));
        checks.push(compose::check(&report.info.tcb_info.app_compose));
    }
    checks.extend(extra);
    checks.sort_by_key(|c| c.link);

    Ok(Review {
        watcher: concat!("sealed-review-watcher/", env!("CARGO_PKG_VERSION")),
        host: bundle.host.clone(),
        fetched_at: bundle.fetched_at,
        tier: tier(&checks, role.required()),
        facts: facts(&report, &vm, td.as_ref()),
        checks,
    })
}

/// Tests on a recorded NEAR bundle, built only where the bundle is present (see `build.rs`).
#[cfg(all(test, saved_bundle))]
mod tests;
