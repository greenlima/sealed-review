use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Serialize;

use crate::report::{OhttpAttestation, Report};
use crate::verdict::{Check, Status};

const ID: &str = "ohttp_key_bound";

/// An RFC 9458 key configuration: the key an OHTTP client encrypts its request to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyConfig {
    pub key_id: u8,
    pub kem_id: u16,
    pub public_key: String,
    /// (KDF, AEAD) pairs the gateway accepts.
    pub symmetric: Vec<(u16, u16)>,
}

/// Public key length of each HPKE KEM (RFC 9180, section 7.1).
fn public_key_len(kem_id: u16) -> Option<usize> {
    match kem_id {
        0x0010 => Some(65),
        0x0011 => Some(97),
        0x0012 => Some(133),
        0x0020 => Some(32),
        0x0021 => Some(56),
        _ => None,
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// One key configuration, exactly: key id, KEM, public key, then a non-empty list of (KDF, AEAD).
pub fn parse(bytes: &[u8]) -> Result<KeyConfig> {
    let (&key_id, rest) = bytes.split_first().context("empty key config")?;
    let kem_id = u16_at(rest, 0).context("truncated KEM id")?;
    let npk = public_key_len(kem_id).ok_or_else(|| anyhow!("unknown KEM 0x{kem_id:04x}"))?;
    let public_key = rest.get(2..2 + npk).context("truncated public key")?;
    let declared = usize::from(u16_at(rest, 2 + npk).context("truncated algorithm list")?);
    let algorithms = &rest[4 + npk..];
    if declared == 0 || declared % 4 != 0 || algorithms.len() != declared {
        bail!(
            "algorithm list declares {declared} bytes, {} follow",
            algorithms.len()
        );
    }
    let symmetric = algorithms
        .chunks_exact(4)
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u16::from_be_bytes([c[2], c[3]]),
            )
        })
        .collect();
    Ok(KeyConfig {
        key_id,
        kem_id,
        public_key: hex::encode(public_key),
        symmetric,
    })
}

/// The offered key, as parsed; trusted only as far as `ohttp_key_bound` passes.
pub fn key(report: &Report) -> Option<KeyConfig> {
    parse(&hex::decode(report.ohttp_key_config.as_deref()?).ok()?).ok()
}

/// The key config parses and is signed, over its raw bytes, by the report's Ed25519 signer.
fn bound(
    signing_algo: &str,
    signing_address: &str,
    config_hex: &str,
    attestation: &OhttpAttestation,
) -> Result<KeyConfig> {
    let raw = hex::decode(config_hex).context("ohttp_key_config is not hex")?;
    let config = parse(&raw)?;
    ensure!(
        attestation.key_config.eq_ignore_ascii_case(config_hex),
        "the attestation signs a different key config"
    );
    ensure!(
        signing_algo == "ed25519" && attestation.signing_algo == "ed25519",
        "report signer is {signing_algo}, OHTTP signer is {}; only Ed25519 is checked",
        attestation.signing_algo
    );
    let signer = signing_address.trim_start_matches("0x");
    ensure!(
        attestation.signing_key.eq_ignore_ascii_case(signer),
        "signed by {}, not the report's signer {signer}",
        attestation.signing_key
    );
    let public_key = hex::decode(signer).context("signing address is not hex")?;
    let signature = hex::decode(&attestation.signature).context("signature is not hex")?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&raw, &signature)
        .map_err(|_| anyhow!("Ed25519 signature over the key config does not verify"))?;
    Ok(config)
}

/// Link 4: an offered OHTTP key carries the quote's binding through the report's signer. No check
/// when the endpoint offers none.
pub fn check(report: &Report) -> Option<Check> {
    let offered = (
        report.ohttp_key_config.as_deref(),
        report.ohttp_attestation.as_ref(),
    );
    let (config, attestation) = match offered {
        (None, None) => return None,
        (Some(config), Some(attestation)) => (config, attestation),
        (Some(_), None) => {
            return Some(Check::new(
                4,
                ID,
                Status::Fail,
                "OHTTP key offered unsigned",
            ));
        }
        (None, Some(_)) => {
            return Some(Check::new(
                4,
                ID,
                Status::Fail,
                "OHTTP signature without a key",
            ));
        }
    };
    let check = match bound(
        &report.signing_algo,
        &report.signing_address,
        config,
        attestation,
    ) {
        Ok(c) => Check::new(
            4,
            ID,
            Status::Pass,
            format!(
                "OHTTP key {} (id {}, KEM 0x{:04x}) signed by the report's signer; rests on signer_bound",
                c.public_key, c.key_id, c.kem_id
            ),
        ),
        Err(e) => Check::new(4, ID, Status::Fail, format!("{e:#}")),
    };
    Some(check)
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    const X25519_CONFIG: &str = "010020da8c5a2429c23ca13bc29fbbcf6f665bfc43fb7190b4141aeac79ebcae746d1400080001000100010003";

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn attestation(signer: &Ed25519KeyPair, config_hex: &str) -> OhttpAttestation {
        OhttpAttestation {
            signing_algo: "ed25519".to_owned(),
            signing_key: hex::encode(signer.public_key()),
            key_config: config_hex.to_owned(),
            signature: hex::encode(signer.sign(&hex::decode(config_hex).unwrap())),
        }
    }

    #[test]
    fn parses_x25519_with_two_aeads() {
        let config = parse(&hex::decode(X25519_CONFIG).unwrap()).unwrap();
        assert_eq!((config.key_id, config.kem_id), (1, 0x0020));
        assert_eq!(config.public_key.len(), 64);
        assert_eq!(config.symmetric, vec![(1, 1), (1, 3)]);
    }

    #[test]
    fn rejects_truncated_and_trailing_bytes() {
        let raw = hex::decode(X25519_CONFIG).unwrap();
        assert!(parse(&raw[..raw.len() - 1]).is_err());
        assert!(parse(&[raw.as_slice(), &[0]].concat()).is_err());
        assert!(parse(&raw[..20]).is_err());
    }

    #[test]
    fn rejects_unknown_kem() {
        let mut raw = hex::decode(X25519_CONFIG).unwrap();
        raw[2] = 0x99;
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn bound_signer_passes() {
        let signer = keypair();
        let address = hex::encode(signer.public_key());
        let att = attestation(&signer, X25519_CONFIG);
        assert!(bound("ed25519", &address, X25519_CONFIG, &att).is_ok());
    }

    #[test]
    fn other_signer_fails() {
        let (signer, other) = (keypair(), keypair());
        let address = hex::encode(signer.public_key());
        let att = attestation(&other, X25519_CONFIG);
        assert!(bound("ed25519", &address, X25519_CONFIG, &att).is_err());
    }

    #[test]
    fn swapped_key_fails() {
        let signer = keypair();
        let address = hex::encode(signer.public_key());
        let mut att = attestation(&signer, X25519_CONFIG);
        let swapped = X25519_CONFIG.replacen("da8c", "da8d", 1);
        assert!(bound("ed25519", &address, &swapped, &att).is_err());
        att.key_config = swapped.clone();
        assert!(bound("ed25519", &address, &swapped, &att).is_err());
    }
}
