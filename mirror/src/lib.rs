//! The signed feed's mirror on NEAR.
//!
//! Anyone may submit an entry; it is kept only if one of the feed keys signed it (ES256, low-S)
//! and that key is not retired, its sequence number is the head's plus one and its `prev` is the
//! SHA-256 of the head's compact JWS. An entry may retire another feed key instead of carrying a
//! verdict. The contract account's keys are deleted after initialisation, so these rules cannot change.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use near_sdk::serde::Deserialize;
use near_sdk::serde::de::DeserializeOwned;
use near_sdk::serde_json::{self, Value, json};
use near_sdk::store::{IterableMap, Vector};
use near_sdk::{BorshStorageKey, PanicOnDefault, Promise, env, near, require};

const PROFILE: &str = "tag:ietf.org,2026:rats/ear#04";
const ALG: &str = "ES256";
const TIERS: [&str; 4] = ["affirming", "warning", "none", "contraindicated"];
const PAGE: u64 = 20;
const EVENT_STANDARD: &str = "sealed-review-mirror";
/// Feed keys the contract may be created with.
const MAX_KEYS: usize = 4;
/// DER SubjectPublicKeyInfo prefix of an uncompressed P-256 public key.
const SPKI_P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum Prefix {
    Entries,
    Hosts,
}

/// A host's latest verdict, as the feed's own summary computes it.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Latest {
    pub seq: u64,
    pub status: String,
    pub exp: u64,
    pub corrected_by: Option<u64>,
}

#[near(serializers = [json])]
#[derive(Debug, PartialEq, Eq)]
pub struct Current {
    pub host: String,
    pub latest: Latest,
}

#[near(serializers = [json])]
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub sha256: String,
}

#[near(serializers = [json])]
#[derive(Debug, PartialEq, Eq)]
pub struct FeedKey {
    pub kid: String,
    /// Compressed SEC1 point, hex.
    pub public_key: String,
    pub retired_by: Option<u64>,
}

#[near(serializers = [borsh])]
struct Pinned {
    key: [u8; 33],
    kid: String,
    retired_by: Option<u64>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Header {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Claims {
    eat_profile: String,
    iat: u64,
    exp: Option<u64>,
    ear_status: Option<String>,
    #[serde(default)]
    submods: serde_json::Map<String, Value>,
    sr_feed: Link,
    sr_scope: Option<Scope>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Link {
    seq: u64,
    prev: Option<String>,
    corrects: Option<Correction>,
    retires: Option<Retirement>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Retirement {
    kid: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Correction {
    seq: u64,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Scope {
    host: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct HostOnly {
    sr_scope: Scope,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Mirror {
    keys: Vec<Pinned>,
    head: Option<String>,
    entries: Vector<String>,
    hosts: IterableMap<String, Latest>,
}

fn fail(message: &str) -> ! {
    env::panic_str(message)
}

fn decode<T: DeserializeOwned>(part: &str, what: &str) -> T {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .unwrap_or_else(|_| fail(&format!("{what} is not base64url")));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| fail(&format!("{what} is not the expected JSON")))
}

/// The compressed point and RFC 7638 thumbprint of a PEM P-256 public key, as the watcher names it.
fn parse_key(pem: &str) -> ([u8; 33], String) {
    require!(
        pem.contains("-----BEGIN PUBLIC KEY-----"),
        "not a PEM public key"
    );
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(body)
        .unwrap_or_else(|_| fail("PEM body is not base64"));
    let point = der
        .strip_prefix(SPKI_P256.as_slice())
        .filter(|p| p.len() == 65 && p[0] == 0x04)
        .unwrap_or_else(|| fail("not an uncompressed P-256 public key"));
    let (x, y) = point[1..].split_at(32);
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y)
    );
    let mut key = [0u8; 33];
    key[0] = 0x02 | (y[31] & 1);
    key[1..].copy_from_slice(x);
    (
        key,
        URL_SAFE_NO_PAD.encode(env::sha256_array(jwk.as_bytes())),
    )
}

fn payload(jws: &str) -> &str {
    jws.split('.')
        .nth(1)
        .unwrap_or_else(|| fail("not a compact JWS"))
}

#[near]
impl Mirror {
    /// Called once, by the contract account itself, in the deployment transaction.
    #[init]
    #[private]
    pub fn new(public_keys: Vec<String>) -> Self {
        require!(
            (1..=MAX_KEYS).contains(&public_keys.len()),
            format!("give one to {MAX_KEYS} feed keys")
        );
        let keys: Vec<Pinned> = public_keys
            .iter()
            .map(|pem| {
                let (key, kid) = parse_key(pem);
                Pinned {
                    key,
                    kid,
                    retired_by: None,
                }
            })
            .collect();
        let distinct = keys
            .iter()
            .enumerate()
            .all(|(i, k)| keys[..i].iter().all(|o| o.kid != k.kid));
        require!(distinct, "a feed key is given twice");
        Self {
            keys,
            head: None,
            entries: Vector::new(Prefix::Entries),
            hosts: IterableMap::new(Prefix::Hosts),
        }
    }

    /// Keeps the next entry; the attached deposit pays for its storage and the rest is refunded.
    #[payable]
    pub fn append(&mut self, jws: String) -> u64 {
        let before = env::storage_usage();
        let seq = self.accept(&jws);
        self.entries.flush();
        self.hosts.flush();
        env::state_write(self);
        let used = env::storage_usage().saturating_sub(before);
        let cost = env::storage_byte_cost().saturating_mul(u128::from(used));
        let attached = env::attached_deposit();
        require!(
            attached >= cost,
            format!(
                "attach at least {} yoctoNEAR for storage",
                cost.as_yoctonear()
            )
        );
        let refund = attached.saturating_sub(cost);
        if !refund.is_zero() {
            Promise::new(env::predecessor_account_id())
                .transfer(refund)
                .detach();
        }
        seq
    }

    pub fn head(&self) -> Option<Head> {
        self.head.as_ref().map(|sha256| Head {
            seq: u64::from(self.entries.len()),
            sha256: sha256.clone(),
        })
    }

    pub fn entry(&self, seq: u64) -> Option<String> {
        let index = u32::try_from(seq.checked_sub(1)?).ok()?;
        self.entries.get(index).cloned()
    }

    /// Up to 20 entries from sequence number `from`.
    pub fn entries(&self, from: u64, limit: u64) -> Vec<String> {
        let skip = usize::try_from(from.saturating_sub(1)).unwrap_or(usize::MAX);
        let take = usize::try_from(limit.min(PAGE)).unwrap_or(0);
        self.entries.iter().skip(skip).take(take).cloned().collect()
    }

    pub fn latest(&self, host: String) -> Option<Latest> {
        self.hosts.get(&host).cloned()
    }

    pub fn hosts(&self) -> Vec<Current> {
        self.hosts
            .iter()
            .map(|(host, latest)| Current {
                host: host.clone(),
                latest: latest.clone(),
            })
            .collect()
    }

    pub fn feed_keys(&self) -> Vec<FeedKey> {
        self.keys
            .iter()
            .map(|k| FeedKey {
                kid: k.kid.clone(),
                public_key: hex::encode(k.key),
                retired_by: k.retired_by,
            })
            .collect()
    }
}

impl Mirror {
    fn accept(&mut self, jws: &str) -> u64 {
        let (input, signature) = jws
            .rsplit_once('.')
            .unwrap_or_else(|| fail("not a compact JWS"));
        let (header, payload) = input
            .split_once('.')
            .filter(|(_, p)| !p.contains('.'))
            .unwrap_or_else(|| fail("not a compact JWS"));
        let header: Header = decode(header, "header");
        require!(header.alg == ALG, "algorithm is not ES256");
        let signer = self
            .keys
            .iter()
            .position(|k| k.kid == header.kid)
            .unwrap_or_else(|| fail("signed by another key"));
        require!(
            self.keys[signer].retired_by.is_none(),
            "signed by a retired key"
        );
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|s| s.try_into().ok())
            .unwrap_or_else(|| fail("signature is not 64 bytes of base64url"));
        require!(
            env::p256_signature_is_low_s(&signature),
            "signature is not low-S"
        );
        require!(
            env::p256_verify(
                &signature,
                &env::sha256_array(input.as_bytes()),
                &self.keys[signer].key
            ),
            "signature does not verify"
        );

        let mut claims: Claims = decode(payload, "claims");
        require!(claims.eat_profile == PROFILE, "unknown profile");
        let seq = u64::from(self.entries.len()) + 1;
        require!(
            claims.sr_feed.seq == seq && claims.sr_feed.prev == self.head,
            "entry does not follow the head"
        );
        let sha256 = hex::encode(env::sha256_array(jws.as_bytes()));
        let event = match claims.sr_feed.retires.take() {
            Some(r) => self.retire(&claims, &r.kid, signer, seq, &sha256),
            None => self.record(claims, seq, &sha256),
        };
        env::log_str(&format!(
            "EVENT_JSON:{}",
            json!({
                "standard": EVENT_STANDARD,
                "version": "1.0.0",
                "event": event.0,
                "data": [event.1],
            })
        ));
        self.entries.push(jws.to_owned());
        self.head = Some(sha256);
        seq
    }

    /// A verdict, or a correction of an earlier one.
    fn record(&mut self, claims: Claims, seq: u64, sha256: &str) -> (&'static str, Value) {
        let (Some(status), Some(exp), Some(scope)) =
            (claims.ear_status, claims.exp, claims.sr_scope)
        else {
            fail("a verdict needs exp, ear_status and sr_scope")
        };
        require!(TIERS.contains(&status.as_str()), "unknown status");
        let host = scope.host;
        match &claims.sr_feed.corrects {
            Some(c) => self.correct(c.seq, seq, &host, &status),
            None => {
                require!(claims.iat <= exp, "entry expires before it is issued");
                self.hosts.insert(
                    host.clone(),
                    Latest {
                        seq,
                        status: status.clone(),
                        exp,
                        corrected_by: None,
                    },
                );
            }
        }
        let data = json!({
            "seq": seq,
            "sha256": sha256,
            "host": host,
            "status": status,
            "corrects": claims.sr_feed.corrects.map(|c| c.seq),
        });
        ("append", data)
    }

    /// Another feed key, not yet retired, signs the entry that retires `kid`; so one key always remains.
    fn retire(
        &mut self,
        claims: &Claims,
        kid: &str,
        signer: usize,
        seq: u64,
        sha256: &str,
    ) -> (&'static str, Value) {
        require!(
            claims.exp.is_none()
                && claims.ear_status.is_none()
                && claims.sr_scope.is_none()
                && claims.submods.is_empty()
                && claims.sr_feed.corrects.is_none(),
            "a retirement carries no verdict"
        );
        let target = self
            .keys
            .iter()
            .position(|k| k.kid == kid)
            .unwrap_or_else(|| fail("retires a key the feed does not have"));
        require!(target != signer, "a key cannot retire itself");
        require!(
            self.keys[target].retired_by.is_none(),
            "the key is already retired"
        );
        self.keys[target].retired_by = Some(seq);
        let data = json!({ "seq": seq, "sha256": sha256, "kid": kid });
        ("retire", data)
    }

    /// A correction restates an earlier entry of the same host; it changes the host's verdict only
    /// if that entry is still the host's latest.
    fn correct(&mut self, target: u64, seq: u64, host: &str, status: &str) {
        require!(target < seq, "a correction must name an earlier entry");
        let stored = self
            .entry(target)
            .unwrap_or_else(|| fail("corrected entry is missing"));
        let original: HostOnly = decode(payload(&stored), "corrected entry");
        require!(
            original.sr_scope.host == host,
            "a correction must name an entry of the same host"
        );
        if let Some(latest) = self.hosts.get_mut(host)
            && latest.seq == target
        {
            latest.status = status.to_owned();
            latest.corrected_by = Some(seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use near_sdk::test_utils::{VMContextBuilder, get_logs};
    use near_sdk::{AccountId, NearToken, testing_env};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    const HOST: &str = "model.example";
    /// Order of the P-256 group.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    fn account(name: &str) -> AccountId {
        name.parse().unwrap()
    }

    fn call_from(predecessor: &str, deposit: NearToken) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(account("mirror.testnet"))
                .predecessor_account_id(account(predecessor))
                .attached_deposit(deposit)
                .build()
        );
    }

    fn negate(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            out[i] = d.rem_euclid(256) as u8;
        }
        out
    }

    struct Signer {
        pair: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl Signer {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self { pair, rng }
        }

        fn pem(&self) -> String {
            let der = [SPKI_P256.as_slice(), self.pair.public_key().as_ref()].concat();
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                STANDARD.encode(der)
            )
        }

        /// A compact JWS as `watcher seal` writes it, with `s` low or high as asked.
        fn jws(&self, kid: &str, claims: &Value, high_s: bool) -> String {
            let header =
                URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#));
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
            let input = format!("{header}.{payload}");
            let mut sig: [u8; 64] = self
                .pair
                .sign(&self.rng, input.as_bytes())
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap();
            if env::p256_signature_is_low_s(&sig) == high_s {
                let s = negate(&sig[32..]);
                sig[32..].copy_from_slice(&s);
            }
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
        }
    }

    fn claims(seq: u64, prev: Option<&str>, host: &str, status: &str) -> Value {
        let mut link = json!({ "seq": seq });
        if let Some(prev) = prev {
            link["prev"] = prev.into();
        }
        json!({
            "eat_profile": PROFILE,
            "iat": 100,
            "exp": 200,
            "ear_status": status,
            "submods": {},
            "sr_feed": link,
            "sr_scope": { "host": host, "tries": 5, "machines": 1 },
        })
    }

    /// Key A, which signs, and key B, kept offline.
    struct Fixture {
        signer: Signer,
        backup: Signer,
        mirror: Mirror,
        kid: String,
        backup_kid: String,
    }

    impl Fixture {
        fn new() -> Self {
            call_from("mirror.testnet", NearToken::from_near(0));
            let (signer, backup) = (Signer::new(), Signer::new());
            let mirror = Mirror::new(vec![signer.pem(), backup.pem()]);
            let keys = mirror.feed_keys();
            Self {
                signer,
                backup,
                mirror,
                kid: keys[0].kid.clone(),
                backup_kid: keys[1].kid.clone(),
            }
        }

        fn next(&self, host: &str, status: &str) -> Value {
            let head = self.mirror.head();
            let seq = head.as_ref().map_or(1, |h| h.seq + 1);
            claims(seq, head.as_ref().map(|h| h.sha256.as_str()), host, status)
        }

        /// An entry retiring `kid`, next after the head.
        fn retirement(&self, kid: &str) -> Value {
            let mut claims = self.next(HOST, "none");
            for field in ["exp", "ear_status", "submods", "sr_scope"] {
                claims.as_object_mut().unwrap().remove(field);
            }
            claims["sr_feed"]["retires"] = json!({ "kid": kid, "reason": "YubiKey lost" });
            claims
        }

        fn append(&mut self, claims: &Value) -> u64 {
            call_from("relay.testnet", NearToken::from_near(1));
            let jws = self.signer.jws(&self.kid, claims, false);
            self.mirror.append(jws)
        }

        fn append_by_backup(&mut self, claims: &Value) -> u64 {
            call_from("relay.testnet", NearToken::from_near(1));
            let jws = self.backup.jws(&self.backup_kid, claims, false);
            self.mirror.append(jws)
        }
    }

    #[test]
    fn entries_chain() {
        let mut f = Fixture::new();
        assert_eq!(f.mirror.head(), None);
        assert_eq!(f.append(&f.next(HOST, "warning")), 1);
        let first = f.mirror.entry(1).unwrap();
        assert_eq!(
            f.mirror.head().unwrap().sha256,
            hex::encode(env::sha256_array(first.as_bytes()))
        );
        assert_eq!(f.append(&f.next("other.example", "affirming")), 2);
        assert_eq!(f.append(&f.next(HOST, "none")), 3);
        assert_eq!(f.mirror.head().unwrap().seq, 3);
        assert_eq!(f.mirror.entries(2, 50).len(), 2);
        assert_eq!(
            f.mirror.latest(HOST.into()),
            Some(Latest {
                seq: 3,
                status: "none".into(),
                exp: 200,
                corrected_by: None
            })
        );
        assert_eq!(f.mirror.hosts().len(), 2);
        assert!(get_logs()[0].contains(r#""event":"append""#));
    }

    #[test]
    fn the_key_id_is_the_watchers() {
        let f = Fixture::new();
        let der = STANDARD
            .decode(
                f.signer
                    .pem()
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let point = &der[SPKI_P256.len()..];
        let jwk = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&point[1..33]),
            URL_SAFE_NO_PAD.encode(&point[33..])
        );
        assert_eq!(
            f.kid,
            URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, jwk.as_bytes()))
        );
    }

    #[test]
    fn either_key_signs_until_one_is_retired() {
        let mut f = Fixture::new();
        assert_eq!(f.append(&f.next(HOST, "warning")), 1);
        assert_eq!(f.append_by_backup(&f.next(HOST, "affirming")), 2);
        assert_eq!(f.append_by_backup(&f.retirement(&f.kid.clone())), 3);
        assert!(get_logs()[0].contains(r#""event":"retire""#));
        let keys = f.mirror.feed_keys();
        assert_eq!((keys[0].retired_by, keys[1].retired_by), (Some(3), None));
        assert_eq!(f.mirror.latest(HOST.into()).unwrap().seq, 2);
        assert_eq!(f.append_by_backup(&f.next(HOST, "none")), 4);
    }

    #[test]
    #[should_panic(expected = "signed by a retired key")]
    fn a_retired_key_is_refused() {
        let mut f = Fixture::new();
        f.append_by_backup(&f.retirement(&f.kid.clone()));
        f.append(&f.next(HOST, "affirming"));
    }

    #[test]
    #[should_panic(expected = "a key cannot retire itself")]
    fn a_key_cannot_retire_itself() {
        let mut f = Fixture::new();
        f.append(&f.retirement(&f.kid.clone()));
    }

    #[test]
    #[should_panic(expected = "retires a key the feed does not have")]
    fn a_stranger_cannot_be_retired() {
        let mut f = Fixture::new();
        f.append(&f.retirement("stranger"));
    }

    #[test]
    #[should_panic(expected = "a retirement carries no verdict")]
    fn a_retirement_carries_no_verdict() {
        let mut f = Fixture::new();
        let mut claims = f.retirement(&f.backup_kid.clone());
        claims["ear_status"] = "affirming".into();
        f.append(&claims);
    }

    #[test]
    #[should_panic(expected = "a feed key is given twice")]
    fn keys_are_distinct() {
        call_from("mirror.testnet", NearToken::from_near(0));
        let signer = Signer::new();
        Mirror::new(vec![signer.pem(), signer.pem()]);
    }

    #[test]
    #[should_panic(expected = "signature does not verify")]
    fn another_key_is_refused() {
        let mut f = Fixture::new();
        let claims = f.next(HOST, "affirming");
        let forged = Signer::new().jws(&f.kid, &claims, false);
        call_from("relay.testnet", NearToken::from_near(1));
        f.mirror.append(forged);
    }

    #[test]
    #[should_panic(expected = "signature does not verify")]
    fn a_changed_entry_is_refused() {
        let mut f = Fixture::new();
        let jws = f.signer.jws(&f.kid, &f.next(HOST, "warning"), false);
        let mut parts: Vec<&str> = jws.split('.').collect();
        let changed =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&f.next(HOST, "affirming")).unwrap());
        parts[1] = &changed;
        call_from("relay.testnet", NearToken::from_near(1));
        f.mirror.append(parts.join("."));
    }

    #[test]
    #[should_panic(expected = "signature is not low-S")]
    fn a_high_s_signature_is_refused() {
        let mut f = Fixture::new();
        let jws = f.signer.jws(&f.kid, &f.next(HOST, "warning"), true);
        call_from("relay.testnet", NearToken::from_near(1));
        f.mirror.append(jws);
    }

    #[test]
    #[should_panic(expected = "entry does not follow the head")]
    fn a_gap_is_refused() {
        let mut f = Fixture::new();
        f.append(&f.next(HOST, "warning"));
        f.append(&claims(3, None, HOST, "warning"));
    }

    #[test]
    #[should_panic(expected = "entry does not follow the head")]
    fn a_replayed_entry_is_refused() {
        let mut f = Fixture::new();
        f.append(&f.next(HOST, "warning"));
        let first = f.mirror.entry(1).unwrap();
        call_from("relay.testnet", NearToken::from_near(1));
        f.mirror.append(first);
    }

    #[test]
    fn a_correction_replaces_the_status() {
        let mut f = Fixture::new();
        f.append(&f.next(HOST, "affirming"));
        let mut correction = f.next(HOST, "contraindicated");
        correction["sr_feed"]["corrects"] = json!({ "seq": 1, "reason": "wrong image" });
        assert_eq!(f.append(&correction), 2);
        let latest = f.mirror.latest(HOST.into()).unwrap();
        assert_eq!(
            (latest.seq, latest.status.as_str(), latest.corrected_by),
            (1, "contraindicated", Some(2))
        );
    }

    #[test]
    #[should_panic(expected = "a correction must name an entry of the same host")]
    fn a_correction_of_another_host_is_refused() {
        let mut f = Fixture::new();
        f.append(&f.next(HOST, "affirming"));
        let mut correction = f.next("other.example", "contraindicated");
        correction["sr_feed"]["corrects"] = json!({ "seq": 1, "reason": "wrong host" });
        f.append(&correction);
    }

    #[test]
    #[should_panic(expected = "for storage")]
    fn storage_must_be_paid() {
        let mut f = Fixture::new();
        let jws = f.signer.jws(&f.kid, &f.next(HOST, "warning"), false);
        call_from("relay.testnet", NearToken::from_yoctonear(1));
        f.mirror.append(jws);
    }

    /// Entries sealed by the watcher: `MIRROR_FEED=<dir with 000001.jwt…> MIRROR_KEY=<pem>[,<pem>] cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn watcher_entries_are_accepted() {
        let dir = std::env::var("MIRROR_FEED").unwrap();
        let pems = std::env::var("MIRROR_KEY")
            .unwrap()
            .split(',')
            .map(|path| std::fs::read_to_string(path).unwrap())
            .collect();
        call_from("mirror.testnet", NearToken::from_near(0));
        let mut mirror = Mirror::new(pems);
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "jwt"))
            .collect();
        names.sort();
        assert!(!names.is_empty());
        for (i, path) in names.iter().enumerate() {
            call_from("relay.testnet", NearToken::from_near(1));
            let jws = std::fs::read_to_string(path).unwrap().trim().to_owned();
            assert_eq!(mirror.append(jws), i as u64 + 1);
        }
    }
}
