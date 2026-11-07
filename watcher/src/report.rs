use anyhow::Context;
use dstack_types::VmConfig;
use serde::Deserialize;

/// The fields of a NEAR model endpoint's `/v1/attestation/report` that the checks read.
#[derive(Debug, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub model_name: Option<String>,
    pub signing_address: String,
    pub signing_algo: String,
    pub request_nonce: String,
    pub intel_quote: String,
    #[serde(default)]
    pub tls_cert_fingerprint: Option<String>,
    #[serde(default)]
    pub nvidia_payload: Option<String>,
    pub info: Info,
    #[serde(default)]
    pub compose_manager_attestation: Option<ComposeManager>,
    /// RFC 9458 key configuration, hex.
    #[serde(default)]
    pub ohttp_key_config: Option<String>,
    #[serde(default)]
    pub ohttp_attestation: Option<OhttpAttestation>,
}

/// The report signer's signature over the OHTTP key configuration.
#[derive(Debug, Deserialize)]
pub struct OhttpAttestation {
    pub signing_algo: String,
    pub signing_key: String,
    pub key_config: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct Info {
    pub app_id: String,
    pub instance_id: String,
    pub app_name: String,
    pub vm_config: String,
    pub tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
pub struct TcbInfo {
    pub app_compose: String,
    pub event_log: Vec<Event>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub imr: u32,
    pub event_type: u32,
    pub digest: String,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub event_payload: String,
}

/// The launcher's own attestation: its action log, bound to a quote with the client nonce.
#[derive(Debug, Deserialize)]
pub struct ComposeManager {
    pub actions_hash: String,
    pub nonce: String,
    pub nonce_source: String,
    pub quote: String,
    /// Kept as JSON values: `actions_hash` is the SHA-256 of their compact, key-sorted encoding.
    pub actions: Vec<serde_json::Value>,
}

impl Report {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }

    pub fn vm_config(&self) -> anyhow::Result<VmConfig> {
        serde_json::from_str(&self.info.vm_config).context("vm_config is not a dstack VmConfig")
    }
}
