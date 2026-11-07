use dcap_qvl::quote::TDReport10;
use sha2::{Digest, Sha256};

use crate::report::Report;
use crate::verdict::Check;

/// `01 || SHA-256(app_compose) || 15 zero bytes`, as NEAR's MRCONFIGID carries it.
pub fn expected_config_id(app_compose: &str) -> [u8; 48] {
    let mut id = [0u8; 48];
    id[0] = 1;
    id[1..33].copy_from_slice(&Sha256::digest(app_compose.as_bytes()));
    id
}

fn signing_identity(report: &Report) -> Option<Vec<u8>> {
    let identity = hex::decode(report.signing_address.trim_start_matches("0x")).ok()?;
    let expected = match report.signing_algo.as_str() {
        "ecdsa" => 20,
        "ed25519" => 32,
        _ => return None,
    };
    (identity.len() == expected).then_some(identity)
}

/// First half of NEAR's report_data: the signer, hashed with the TLS key when one is bound.
fn bound_identity(identity: &[u8], fingerprint: Option<&[u8]>) -> [u8; 32] {
    match fingerprint {
        Some(fp) => Sha256::new()
            .chain_update(identity)
            .chain_update(fp)
            .finalize()
            .into(),
        None => {
            let mut padded = [0u8; 32];
            padded[..identity.len()].copy_from_slice(identity);
            padded
        }
    }
}

/// Whether the TLS key the report binds is the one on the connection that returned it.
pub fn tls(report: &Report, peer_spki_sha256: &str) -> Check {
    let fingerprint = report.tls_cert_fingerprint.as_deref();
    Check::from_bool(
        4,
        "tls_bound",
        fingerprint.is_some_and(|fp| fp.eq_ignore_ascii_case(peer_spki_sha256)),
        format!(
            "attested TLS key {} vs the connection's {peer_spki_sha256}",
            fingerprint.unwrap_or("none")
        ),
    )
}

/// Links 4–5 read from the verified quote: freshness, signer binding, configuration.
pub fn checks(report: &Report, td: &TDReport10, nonce: &str) -> Vec<Check> {
    let nonce_bytes = hex::decode(nonce).unwrap_or_default();
    let fingerprint_bytes = report
        .tls_cert_fingerprint
        .as_deref()
        .and_then(|fp| hex::decode(fp).ok());
    let identity = signing_identity(report);

    let fresh = nonce_bytes.len() == 32
        && td.report_data[32..] == nonce_bytes[..]
        && report.request_nonce.eq_ignore_ascii_case(nonce);
    let signer = identity
        .as_deref()
        .is_some_and(|id| td.report_data[..32] == bound_identity(id, fingerprint_bytes.as_deref()));
    let config = td.mr_config_id == expected_config_id(&report.info.tcb_info.app_compose);

    vec![
        Check::from_bool(
            4,
            "nonce_fresh",
            fresh,
            "report_data[32..64] and the echoed nonce equal our nonce",
        ),
        Check::from_bool(
            4,
            "signer_bound",
            signer,
            format!(
                "{} key {} bound with the TLS key in report_data[0..32]",
                report.signing_algo, report.signing_address
            ),
        ),
        Check::from_bool(
            5,
            "config_measured",
            config,
            "MRCONFIGID = 01 || SHA-256(app_compose) || 0^15",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_identity_is_right_padded() {
        let id = [0xab_u8; 20];
        let bound = bound_identity(&id, None);
        assert_eq!(&bound[..20], &id);
        assert_eq!(&bound[20..], &[0u8; 12]);
    }

    #[test]
    fn config_id_layout() {
        let id = expected_config_id("{}");
        assert_eq!(id[0], 1);
        assert_eq!(&id[1..33], Sha256::digest(b"{}").as_slice());
        assert_eq!(&id[33..], &[0u8; 15]);
    }
}
