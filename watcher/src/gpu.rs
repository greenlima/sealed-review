use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::{Decode, Encode};
use ring::signature::{
    ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
    VerificationAlgorithm,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::bundle::{Gpu, Jwk};
use crate::verdict::{Check, Status};

/// SHA-256 of the NRAS signing intermediates seen in NVIDIA's JWKS on 2026-10-30. NVIDIA does not
/// publish the NRAS root ("NVIDIA Attestation Service CA 001") in our sources, so a new intermediate
/// leaves the GPU link unknown until it is reviewed and added here.
pub const NRAS_INTERMEDIATES: [&str; 2] = [
    "2df8907cf4d6c277b855d407ec178a649930a8e73f7294e8fce66e6ee27c5175",
    "38e3daf3cdbd5243bb15dd7993edcdd83a7238cb6745b980f8f3bf0a31a0d343",
];
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const RSA_WITH_SHA256: &str = "1.2.840.113549.1.1.11";
const MAX_TOKEN_AGE_SECS: u64 = 600;
/// The claim set reviewed against NVIDIA's claims guide; NRAS answers with it when the payload names none.
const CLAIMS_VERSION: &str = "2.0";

#[derive(Debug, Deserialize)]
struct Header {
    kid: String,
    alg: String,
}

#[derive(Debug, Deserialize)]
struct Overall {
    #[serde(rename = "x-nvidia-ver")]
    version: String,
    #[serde(rename = "x-nvidia-overall-att-result")]
    result: bool,
    eat_nonce: String,
    iat: u64,
    submods: BTreeMap<String, (String, (String, String))>,
}

#[derive(Debug, Deserialize)]
struct Detached {
    eat_nonce: String,
    measres: String,
    secboot: bool,
    dbgstat: String,
    hwmodel: String,
    #[serde(rename = "x-nvidia-gpu-arch-check")]
    arch_check: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-signature-verified")]
    report_signature: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain-validated")]
    report_cert_chain: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match")]
    report_nonce: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-signature-verified")]
    driver_rim: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-signature-verified")]
    vbios_rim: bool,
    #[serde(rename = "x-nvidia-attestation-warning", default)]
    warning: Option<serde_json::Value>,
    #[serde(rename = "x-nvidia-gpu-driver-version")]
    driver: String,
    #[serde(rename = "x-nvidia-gpu-vbios-version")]
    vbios: String,
}

/// NRAS answers `[["JWT", overall], {"GPU-0": detached, ...}]`.
#[derive(Debug, Deserialize)]
struct Response((String, String), BTreeMap<String, String>);

/// Why a GPU verdict could not be affirmed: evidence we cannot appraise, or evidence that is wrong.
#[derive(Debug)]
pub enum Problem {
    Unverifiable(String),
    Invalid(String),
}

impl Problem {
    fn check(self) -> Check {
        match self {
            Problem::Unverifiable(e) => Check::new(8, "gpu", Status::Unknown, e),
            Problem::Invalid(e) => Check::new(8, "gpu", Status::Fail, e),
        }
    }
}

fn invalid(e: impl std::fmt::Display) -> Problem {
    Problem::Invalid(e.to_string())
}

fn b64url(part: &str) -> Result<Vec<u8>, Problem> {
    URL_SAFE_NO_PAD.decode(part).map_err(invalid)
}

/// The kids an NRAS response is signed with, so `fetch` saves only those JWKS entries.
pub fn signing_kids(response: &str) -> BTreeSet<String> {
    let Ok(Response((_, overall), detached)) = serde_json::from_str::<Response>(response) else {
        return BTreeSet::new();
    };
    std::iter::once(overall.as_str())
        .chain(detached.values().map(String::as_str))
        .filter_map(|t| t.split('.').next())
        .filter_map(|h| URL_SAFE_NO_PAD.decode(h).ok())
        .filter_map(|h| serde_json::from_slice::<Header>(&h).ok())
        .map(|h| h.kid)
        .collect()
}

fn unix(time: &x509_cert::time::Time) -> u64 {
    time.to_unix_duration().as_secs()
}

/// The leaf in `x5c` is signed by a pinned NRAS intermediate and valid at `at`; returns its EC point.
fn signing_key(jwk: &Jwk, at: u64) -> Result<Vec<u8>, Problem> {
    let [leaf, intermediate] = jwk.x5c.as_slice() else {
        return Err(Problem::Unverifiable(format!(
            "{}: x5c is not leaf + intermediate",
            jwk.kid
        )));
    };
    let leaf_der = STANDARD.decode(leaf).map_err(invalid)?;
    let intermediate_der = STANDARD.decode(intermediate).map_err(invalid)?;
    let pin = hex::encode(Sha256::digest(&intermediate_der));
    if !NRAS_INTERMEDIATES.contains(&pin.as_str()) {
        return Err(Problem::Unverifiable(format!(
            "intermediate {pin} is not pinned"
        )));
    }
    let leaf = Certificate::from_der(&leaf_der).map_err(invalid)?;
    let intermediate = Certificate::from_der(&intermediate_der).map_err(invalid)?;
    let algorithm: &dyn VerificationAlgorithm =
        match leaf.signature_algorithm().oid.to_string().as_str() {
            ECDSA_WITH_SHA384 => &ECDSA_P384_SHA384_ASN1,
            RSA_WITH_SHA256 => &RSA_PKCS1_2048_8192_SHA256,
            other => return Err(invalid(format!("leaf signature algorithm {other}"))),
        };
    let tbs = leaf.tbs_certificate().to_der().map_err(invalid)?;
    let issuer_key = intermediate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    UnparsedPublicKey::new(algorithm, issuer_key)
        .verify(&tbs, leaf.signature().raw_bytes())
        .map_err(|_| invalid("leaf certificate is not signed by the pinned intermediate"))?;
    let validity = leaf.tbs_certificate().validity();
    if !(unix(&validity.not_before)..=unix(&validity.not_after)).contains(&at) {
        return Err(invalid(
            "leaf certificate was not valid when the token was issued",
        ));
    }
    Ok(leaf
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec())
}

/// Verifies an ES384 JWT against the JWKS entry its header names; returns the decoded claims.
fn verify_token<T: for<'de> Deserialize<'de>>(
    token: &str,
    keys: &[Jwk],
    at: u64,
) -> Result<T, Problem> {
    let mut parts = token.splitn(3, '.');
    let (Some(header), Some(payload), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("token is not a JWS"));
    };
    let parsed: Header = serde_json::from_slice(&b64url(header)?).map_err(invalid)?;
    if parsed.alg != "ES384" {
        return Err(invalid(format!("token algorithm {}", parsed.alg)));
    }
    let jwk = keys
        .iter()
        .find(|k| k.kid == parsed.kid)
        .ok_or_else(|| Problem::Unverifiable(format!("no saved JWKS key {}", parsed.kid)))?;
    let key = signing_key(jwk, at)?;
    let signed = &token[..header.len() + 1 + payload.len()];
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key)
        .verify(signed.as_bytes(), &b64url(signature)?)
        .map_err(|_| invalid("token signature does not verify"))?;
    serde_json::from_slice(&b64url(payload)?).map_err(invalid)
}

fn appraise_gpu(name: &str, detached: &Detached, nonce: &str) -> Option<String> {
    let problems: Vec<&str> = [
        (detached.eat_nonce.eq_ignore_ascii_case(nonce), "nonce"),
        (detached.measres == "success", "measurements"),
        (detached.secboot, "secure boot"),
        (detached.dbgstat == "disabled", "debug"),
        (detached.arch_check, "architecture"),
        (detached.report_signature, "report signature"),
        (detached.report_cert_chain, "device certificate chain"),
        (detached.report_nonce, "report nonce"),
        (detached.driver_rim, "driver RIM"),
        (detached.vbios_rim, "VBIOS RIM"),
        (detached.warning.is_none(), "attestation warning"),
    ]
    .into_iter()
    .filter_map(|(ok, what)| (!ok).then_some(what))
    .collect();
    (!problems.is_empty()).then(|| format!("{name}: {}", problems.join(", ")))
}

fn appraise(
    gpu: &Gpu,
    nonce: &str,
    fetched_at: u64,
    expected_gpus: u32,
) -> Result<String, Problem> {
    let raw = gpu.response.as_deref().ok_or_else(|| {
        Problem::Unverifiable(
            gpu.error
                .clone()
                .unwrap_or_else(|| "no NRAS response".to_owned()),
        )
    })?;
    let Response((kind, overall_token), detached_tokens) =
        serde_json::from_str(raw).map_err(invalid)?;
    if kind != "JWT" {
        return Err(invalid(format!("overall token type {kind}")));
    }
    let probe: Overall = serde_json::from_slice(&b64url(
        overall_token.split('.').nth(1).unwrap_or_default(),
    )?)
    .map_err(invalid)?;
    if probe.iat.abs_diff(fetched_at) > MAX_TOKEN_AGE_SECS {
        return Err(invalid("NRAS token was not issued during this fetch"));
    }
    let overall: Overall = verify_token(&overall_token, &gpu.keys, probe.iat)?;
    if overall.version != CLAIMS_VERSION {
        return Err(Problem::Unverifiable(format!(
            "claims version {} not reviewed",
            overall.version
        )));
    }
    if !overall.result || !overall.eat_nonce.eq_ignore_ascii_case(nonce) {
        return Err(invalid(format!(
            "overall result {}, nonce matches {}",
            overall.result,
            overall.eat_nonce.eq_ignore_ascii_case(nonce)
        )));
    }
    if overall.submods.len() != detached_tokens.len()
        || overall.submods.len() != expected_gpus as usize
    {
        return Err(invalid(format!(
            "{} GPUs attested, {} detached tokens, vm_config declares {expected_gpus}",
            overall.submods.len(),
            detached_tokens.len()
        )));
    }

    let mut failures = Vec::new();
    let mut models = BTreeSet::new();
    for (name, (_, (algorithm, digest))) in &overall.submods {
        let token = detached_tokens
            .get(name)
            .ok_or_else(|| invalid(format!("{name}: no detached token")))?;
        if algorithm != "SHA-256" || hex::encode(Sha256::digest(token.as_bytes())) != *digest {
            return Err(invalid(format!(
                "{name}: detached token does not match the overall digest"
            )));
        }
        let detached: Detached = verify_token(token, &gpu.keys, probe.iat)?;
        failures.extend(appraise_gpu(name, &detached, nonce));
        models.insert(format!(
            "{} driver {} vbios {}",
            detached.hwmodel, detached.driver, detached.vbios
        ));
    }
    if !failures.is_empty() {
        return Err(invalid(failures.join("; ")));
    }
    Ok(format!(
        "{} GPUs pass NRAS, tokens verified locally: {}",
        overall.submods.len(),
        models.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

/// Link 8: NVIDIA's verdict on every GPU, verified locally; NVSwitch evidence is reported, not required.
pub fn checks(
    gpu: Option<&Gpu>,
    payload: Option<&str>,
    nonce: &str,
    fetched_at: u64,
    gpus: u32,
    switches: u32,
) -> Vec<Check> {
    let payload_nonce = payload
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok())
        .and_then(|p| {
            p.get("nonce")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    let gpu_check = match (gpu, payload_nonce) {
        (_, None) => Check::new(
            8,
            "gpu",
            Status::Fail,
            "no GPU evidence with a nonce in the report",
        ),
        (_, Some(n)) if !n.eq_ignore_ascii_case(nonce) => {
            Check::new(8, "gpu", Status::Fail, "GPU evidence carries another nonce")
        }
        (None, _) => Check::new(8, "gpu", Status::Unknown, "NRAS not queried"),
        (Some(g), _) => match appraise(g, nonce, fetched_at, gpus) {
            Ok(detail) => Check::new(8, "gpu", Status::Pass, detail),
            Err(problem) => problem.check(),
        },
    };
    let switch_check = if switches == 0 {
        Check::new(8, "nvswitch", Status::Pass, "no NVSwitches declared")
    } else {
        Check::new(
            8,
            "nvswitch",
            Status::Warn,
            format!(
                "vm_config declares {switches} NVSwitches and the report carries no switch evidence; \
                 in PPCIe mode NVLink traffic is plain text and NVIDIA attests the switches and topology"
            ),
        )
    };
    vec![gpu_check, switch_check]
}

/// Link 8 for a CPU-only machine: nothing declared and no GPU evidence sent.
pub fn absent(payload: Option<&str>, gpus: u32, switches: u32) -> Check {
    Check::from_bool(
        8,
        "no_gpus",
        payload.is_none() && gpus == 0 && switches == 0,
        format!(
            "vm_config declares {gpus} GPUs and {switches} NVSwitches; GPU evidence {}",
            if payload.is_some() { "sent" } else { "absent" }
        ),
    )
}
