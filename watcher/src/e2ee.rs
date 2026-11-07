//! NEAR's end-to-end encryption, version 2: X25519 with Ed25519 keys, HKDF-SHA256 and
//! XChaCha20-Poly1305. A field is hex of `ephemeral key (32) ‖ nonce (24) ‖ ciphertext and tag`.

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

pub const VERSION: &str = "2";
const INFO: &[u8] = b"ed25519_encryption";
const NONCE: usize = 24;
/// Answer fields NEAR encrypts by default; `content` must be present.
const ANSWER_FIELDS: [&str; 3] = ["content", "reasoning_content", "reasoning"];

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
    Ok(bytes)
}

/// An Ed25519 public key as the X25519 key it encrypts to; low-order points are refused.
fn montgomery(ed25519_hex: &str) -> Result<MontgomeryPoint> {
    let bytes: [u8; 32] = hex::decode(ed25519_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("the model key is not 32 bytes of hex")?;
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .context("the model key is not a curve point")?;
    ensure!(
        !point.is_small_order(),
        "the model key is a low-order point"
    );
    Ok(point.to_montgomery())
}

fn cipher(secret: &[u8; 32], peer: &MontgomeryPoint) -> Result<XChaCha20Poly1305> {
    let shared = peer.mul_clamped(*secret);
    ensure!(shared.0 != [0u8; 32], "the key exchange gave no secret");
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(INFO, &mut key)
        .map_err(|_| anyhow!("key derivation failed"))?;
    Ok(XChaCha20Poly1305::new(&key.into()))
}

fn seal_with(
    plain: &[u8],
    model: &MontgomeryPoint,
    ephemeral: &[u8; 32],
    nonce: &[u8; NONCE],
) -> Result<String> {
    let sealed = cipher(ephemeral, model)?
        .encrypt(XNonce::from_slice(nonce), plain)
        .map_err(|_| anyhow!("encryption failed"))?;
    let public = MontgomeryPoint::mul_base_clamped(*ephemeral);
    Ok(hex::encode(
        [public.as_bytes(), nonce.as_slice(), &sealed].concat(),
    ))
}

/// The client's side of one request: a fresh key the answer is encrypted to.
pub struct Client {
    secret: [u8; 32],
    model: MontgomeryPoint,
    model_key: String,
}

impl Client {
    /// For the model's Ed25519 key, in hex, as its attested report gives it.
    pub fn new(model_key: &str) -> Result<Self> {
        Ok(Self {
            secret: random()?,
            model: montgomery(model_key)?,
            model_key: model_key.to_ascii_lowercase(),
        })
    }

    /// The client's Ed25519 public key, in hex, for `X-Client-Pub-Key`.
    pub fn public_key(&self) -> String {
        hex::encode(
            EdwardsPoint::mul_base_clamped(self.secret)
                .compress()
                .as_bytes(),
        )
    }

    pub fn model_key(&self) -> &str {
        &self.model_key
    }

    /// The headers NEAR's gateway needs to route a request to a machine holding the model key.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("X-Signing-Algo", "ed25519".into()),
            ("X-Client-Pub-Key", self.public_key()),
            ("X-Model-Pub-Key", self.model_key.clone()),
            ("X-Encryption-Version", VERSION.into()),
            ("x-no-aliasing", "true".into()),
        ]
    }

    pub fn seal(&self, plain: &str) -> Result<String> {
        seal_with(plain.as_bytes(), &self.model, &random()?, &random()?)
    }

    pub fn open(&self, field: &str) -> Result<String> {
        let bytes = hex::decode(field).context("an encrypted field is not hex")?;
        ensure!(bytes.len() > 32 + NONCE, "an encrypted field is too short");
        let (public, rest) = bytes.split_at(32);
        let (nonce, sealed) = rest.split_at(NONCE);
        let peer = MontgomeryPoint(public.try_into()?);
        let plain = cipher(&self.secret, &peer)?
            .decrypt(XNonce::from_slice(nonce), sealed)
            .map_err(|_| anyhow!("an encrypted field does not decrypt to our key"))?;
        String::from_utf8(plain).context("a decrypted field is not text")
    }

    /// Decrypts every encrypted field of each choice in place; an answer without encrypted
    /// `content` is refused, so a plaintext answer never passes for an encrypted one.
    pub fn open_answer(&self, answer: &mut Value) -> Result<()> {
        let choices = answer["choices"]
            .as_array_mut()
            .context("the answer has no choices")?;
        ensure!(!choices.is_empty(), "the answer has no choices");
        for choice in choices {
            let message = choice["message"]
                .as_object_mut()
                .context("a choice has no message")?;
            if !message.get("content").is_some_and(Value::is_string) {
                bail!("a choice has no encrypted content");
            }
            for field in ANSWER_FIELDS {
                let Some(Value::String(sealed)) = message.get(field) else {
                    continue;
                };
                let plain = self
                    .open(sealed)
                    .with_context(|| format!("field {field}"))?;
                message.insert(field.into(), Value::String(plain));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const MODEL_KEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    /// From NEAR's reference algorithm (PyNaCl and cryptography), with fixed randomness.
    const REQUEST: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20333333333333333333333333333333333333333333333333954b8e4658e2e63245ddf4565c65e4c226f9183c154da9845a2f2e99112d3b0703751fc3bf9449865e69d2602f69";
    const CLIENT_KEY: &str = "3b0c3c072fd35b1e72ab89e860d81cf2eaea737a3796510b8c9985c43a7329c8";
    const ANSWER: &str = "38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c676666666666666666666666666666666666666666666666669e215848d75fac03636d592c0cbc98d015f5b3f6b4d3";

    fn client() -> Client {
        Client {
            secret: [0x44; 32],
            model: montgomery(MODEL_KEY).unwrap(),
            model_key: MODEL_KEY.into(),
        }
    }

    #[test]
    fn a_request_matches_the_reference() {
        let sealed = seal_with(
            b"What is the capital of France?",
            &montgomery(MODEL_KEY).unwrap(),
            &[0x22; 32],
            &[0x33; NONCE],
        )
        .unwrap();
        assert_eq!(sealed, REQUEST);
    }

    #[test]
    fn an_answer_from_the_reference_opens() {
        let client = client();
        assert_eq!(client.public_key(), CLIENT_KEY);
        assert_eq!(client.open(ANSWER).unwrap(), "Paris.");
    }

    #[test]
    fn a_changed_or_plain_answer_is_refused() {
        let client = client();
        let mut tampered = ANSWER.to_string();
        tampered.replace_range(tampered.len() - 2.., "00");
        assert!(client.open(&tampered).is_err());
        let mut plain = json!({ "choices": [{ "message": { "content": "Paris." } }] });
        assert!(client.open_answer(&mut plain).is_err());
        let mut empty = json!({ "choices": [{ "message": { "content": null } }] });
        assert!(client.open_answer(&mut empty).is_err());
        let mut sealed = json!({ "choices": [{ "message": { "content": ANSWER } }] });
        client.open_answer(&mut sealed).unwrap();
        assert_eq!(sealed["choices"][0]["message"]["content"], "Paris.");
    }

    #[test]
    fn a_bad_model_key_is_refused() {
        assert!(montgomery("00").is_err());
        let identity = format!("01{}", "00".repeat(31));
        assert!(montgomery(&identity).is_err());
    }
}
