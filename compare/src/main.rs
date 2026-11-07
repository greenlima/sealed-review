use std::{env, fs};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use dcap_qvl::QuoteCollateralV3;
use nearai_inference_sdk::{
    AttestationEventLog, AttestationEvidence, ComposeManagerAttestation, DirectModelAttestation,
    GpuEvidenceRequirement, ModelAttestation, ModelAttestationPolicy, ModelAttestationVerifiers,
    ModelClientBinding, SigningAlgo, SigningIdentity, TcbStatus, TdxQuoteVerificationResult,
    TdxQuoteVerifier, VerificationError, verify_direct_model_attestation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const SDK: &str = "nearai-inference-sdk 0.2.1";

#[derive(Deserialize)]
struct Bundle {
    nonce: String,
    fetched_at: u64,
    report: String,
    collateral: Vec<Saved>,
}

#[derive(Deserialize)]
struct Saved {
    source: String,
    stream: String,
    data: Option<QuoteCollateralV3>,
}

#[derive(Clone, Deserialize)]
struct Wire {
    model_name: String,
    request_nonce: String,
    signing_algo: SigningAlgo,
    signing_address: String,
    signing_public_key: Option<String>,
    intel_quote: String,
    event_log: AttestationEventLog,
    tls_cert_fingerprint: Option<String>,
    report_data: Option<String>,
    nvidia_payload: Option<String>,
    compose_manager_attestation: Option<ComposeManagerAttestation>,
    info: Info,
}

#[derive(Clone, Deserialize)]
struct Info {
    instance_id: Option<String>,
    tcb_info: TcbInfo,
}

#[derive(Clone, Deserialize)]
struct TcbInfo {
    app_compose: String,
}

/// Mirrors the SDK's own mapping from the report's wire shape (its decoder is crate-private).
fn attestation(wire: &Wire, case: &Case) -> DirectModelAttestation {
    let wire = wire.clone();
    let event_log = if case.boot_event_tampered {
        tamper_boot_event(wire.event_log)
    } else {
        wire.event_log
    };
    DirectModelAttestation {
        attestation: ModelAttestation {
            signing_public_key: wire.signing_public_key,
            compose_manager_attestation: wire.compose_manager_attestation,
            evidence: AttestationEvidence {
                nonce: wire.request_nonce,
                signer: SigningIdentity {
                    signing_algo: wire.signing_algo,
                    signing_address: wire.signing_address,
                },
                intel_quote: wire.intel_quote,
                event_log,
                app_compose: wire.info.tcb_info.app_compose,
            },
            reported_quote_data: wire.report_data,
            nvidia_payload: wire.nvidia_payload.filter(|_| case.gpu),
        },
        model_name: wire.model_name,
        instance_id: wire.info.instance_id,
        spki_fingerprint: wire.tls_cert_fingerprint,
    }
}

/// Zeroes the digest of the first RTMR0 event; the quote itself stays genuine.
fn tamper_boot_event(log: AttestationEventLog) -> AttestationEventLog {
    let AttestationEventLog::Entries(mut entries) = log else {
        return log;
    };
    if let Some(digest) = entries
        .iter_mut()
        .find(|event| event.get("imr").and_then(Value::as_u64) == Some(0))
        .and_then(|event| event.get_mut("digest"))
    {
        *digest = Value::String("0".repeat(96));
    }
    AttestationEventLog::Entries(entries)
}

/// The SDK's quote check, fed with collateral the watcher saved, evaluated at fetch time.
struct SavedCollateral {
    collateral: QuoteCollateralV3,
    at: u64,
}

fn failed(reason: &'static str) -> VerificationError {
    VerificationError::QuoteVerificationFailed { reason }
}

#[async_trait]
impl TdxQuoteVerifier for SavedCollateral {
    async fn verify(
        &self,
        intel_quote: &str,
    ) -> Result<TdxQuoteVerificationResult, VerificationError> {
        let quote = decode_hex(intel_quote).ok_or_else(|| failed("invalid_encoding"))?;
        let verified = dcap_qvl::verify::verify(&quote, &self.collateral, self.at)
            .map_err(|_| failed("verifier_error"))?;
        let td = verified
            .report
            .as_td10()
            .ok_or(VerificationError::QuoteUnsupportedReportType)?;
        let tcb_status: TcbStatus = serde_json::from_value(Value::String(verified.status))
            .map_err(|_| failed("unknown_status"))?;
        Ok(TdxQuoteVerificationResult {
            tcb_status,
            advisory_ids: verified.advisory_ids,
            debug_enabled: td.td_attributes[0] & 0x01 != 0,
            report_data: td.report_data.to_vec(),
            mr_config_id: td.mr_config_id.to_vec(),
            rt_mr3: td.rt_mr3.to_vec(),
        })
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Policy {
    SdkDefaults,
    Strict,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Quote {
    /// The SDK's own verifier, fetching Intel's standard collateral now.
    Live,
    SavedStandard,
    SavedEarly,
}

struct Case {
    name: &'static str,
    policy: Policy,
    quote: Quote,
    gpu: bool,
    boot_event_tampered: bool,
}

const CASES: [Case; 7] = [
    Case {
        name: "defaults",
        policy: Policy::SdkDefaults,
        quote: Quote::Live,
        gpu: true,
        boot_event_tampered: false,
    },
    Case {
        name: "strict",
        policy: Policy::Strict,
        quote: Quote::Live,
        gpu: true,
        boot_event_tampered: false,
    },
    Case {
        name: "defaults_early_tcb",
        policy: Policy::SdkDefaults,
        quote: Quote::SavedEarly,
        gpu: true,
        boot_event_tampered: false,
    },
    Case {
        name: "strict_early_tcb",
        policy: Policy::Strict,
        quote: Quote::SavedEarly,
        gpu: true,
        boot_event_tampered: false,
    },
    Case {
        name: "defaults_without_gpu",
        policy: Policy::SdkDefaults,
        quote: Quote::SavedStandard,
        gpu: false,
        boot_event_tampered: false,
    },
    Case {
        name: "strict_without_gpu",
        policy: Policy::Strict,
        quote: Quote::SavedStandard,
        gpu: false,
        boot_event_tampered: false,
    },
    Case {
        name: "defaults_boot_event_tampered",
        policy: Policy::SdkDefaults,
        quote: Quote::SavedStandard,
        gpu: false,
        boot_event_tampered: true,
    },
];

#[derive(Serialize)]
struct Outcome {
    sdk: &'static str,
    case: &'static str,
    policy: Policy,
    quote: Quote,
    gpu_payload: bool,
    boot_event_tampered: bool,
    accepted: bool,
    tcb_status: Option<TcbStatus>,
    advisory_ids: Vec<String>,
    gpu_evidence: Option<String>,
    os_image_hash: Option<String>,
    error: Option<String>,
}

fn policy(policy: Policy) -> Option<ModelAttestationPolicy> {
    match policy {
        Policy::SdkDefaults => None,
        Policy::Strict => Some(ModelAttestationPolicy {
            accepted_tcb_statuses: Some(vec![TcbStatus::UpToDate]),
            gpu_evidence: GpuEvidenceRequirement::Required,
        }),
    }
}

fn saved(bundle: &Bundle, stream: &str) -> Result<SavedCollateral> {
    let collateral = bundle
        .collateral
        .iter()
        .find(|c| c.source == "intel" && c.stream == stream)
        .and_then(|c| c.data.clone())
        .with_context(|| format!("bundle has no Intel {stream} collateral"))?;
    Ok(SavedCollateral {
        collateral,
        at: bundle.fetched_at,
    })
}

async fn run(
    case: &Case,
    wire: &Wire,
    binding: &ModelClientBinding,
    bundle: &Bundle,
) -> Result<Outcome> {
    let quote_verifier = match case.quote {
        Quote::Live => None,
        Quote::SavedStandard => Some(saved(bundle, "standard")?),
        Quote::SavedEarly => Some(saved(bundle, "early")?),
    };
    let verifiers = ModelAttestationVerifiers {
        tdx_quote: quote_verifier.as_ref().map(|v| v as &dyn TdxQuoteVerifier),
        ..Default::default()
    };
    let policy = policy(case.policy);
    let result = verify_direct_model_attestation(
        &attestation(wire, case),
        binding,
        policy.as_ref(),
        verifiers,
    )
    .await;
    let outcome = Outcome {
        sdk: SDK,
        case: case.name,
        policy: case.policy,
        quote: case.quote,
        gpu_payload: case.gpu,
        boot_event_tampered: case.boot_event_tampered,
        accepted: result.is_ok(),
        tcb_status: None,
        advisory_ids: Vec::new(),
        gpu_evidence: None,
        os_image_hash: None,
        error: None,
    };
    Ok(match result {
        Ok(verified) => {
            let model = verified.attestation;
            Outcome {
                tcb_status: Some(model.evidence.tcb_status),
                advisory_ids: model.evidence.advisory_ids,
                gpu_evidence: Some(format!("{:?}", model.gpu_evidence)),
                os_image_hash: model.evidence.deployment.runtime_measurements.os_image_hash,
                ..outcome
            }
        }
        Err(error) => Outcome {
            error: Some(error.to_string()),
            ..outcome
        },
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let Some(path) = env::args().nth(1) else {
        bail!("usage: compare <bundle.json>");
    };
    let bundle: Bundle = serde_json::from_slice(&fs::read(&path)?).context("bundle")?;
    let wire: Wire = serde_json::from_str(&bundle.report).context("report")?;
    let binding = ModelClientBinding {
        nonce: bundle.nonce.clone(),
    };
    for case in &CASES {
        println!(
            "{}",
            serde_json::to_string(&run(case, &wire, &binding, &bundle).await?)?
        );
    }
    Ok(())
}
