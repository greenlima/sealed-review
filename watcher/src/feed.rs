use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bundle::{Bundle, MAX_AGE_SECS, Sweep};
use crate::gateway;
use crate::review::{Facts, Review};
use crate::verdict::{Check, Status, Tier};

pub const PROFILE: &str = "tag:ietf.org,2026:rats/ear#04";
pub const POLICY: &str = "sealed-review/near-dstack/1";
/// An entry expires three days after the oldest fetch it rests on.
pub const LIFETIME_SECS: u64 = 3 * 24 * 60 * 60;
const ALG: &str = "ES256";
const DEVELOPER: &str = "sealed-review";
const BUILD: &str = concat!("sealed-review-watcher/", env!("CARGO_PKG_VERSION"));
const KEY_RELEASE: &str = "key release: the app's keys go to any code its key-release contracts admit; those contracts are not checked";
const NOT_REVIEWED: [&str; 2] = [
    KEY_RELEASE,
    "machines: only the machines the last 24 hours' fetches reached; others may serve the same host",
];
const GATEWAY_NOT_REVIEWED: [&str; 3] = [
    KEY_RELEASE,
    "forwarding: which machine the gateway forwards a request to; the candidates are not an inventory of those machines",
    "answers: response signatures are not checked; a streamed answer is signed by the gateway only",
];
/// DER SubjectPublicKeyInfo prefix of an uncompressed P-256 public key.
const SPKI_P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// Order of the P-256 group, and half of it: the mirror accepts only `s <= N / 2`.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The feed's public key: P-256, named in each entry's header by its RFC 7638 thumbprint.
#[derive(Clone)]
pub struct Key {
    point: Vec<u8>,
    pub kid: String,
}

impl Key {
    pub fn read(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_pem(&text)
    }

    pub fn from_pem(text: &str) -> Result<Self> {
        ensure!(
            text.contains("-----BEGIN PUBLIC KEY-----"),
            "not a PEM public key"
        );
        let body: String = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(body).context("PEM body is not base64")?;
        let point = der
            .strip_prefix(SPKI_P256.as_slice())
            .filter(|p| p.len() == 65 && p[0] == 0x04)
            .context("not an uncompressed P-256 public key")?;
        Ok(Self::from_point(point))
    }

    fn from_point(point: &[u8]) -> Self {
        let jwk = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&point[1..33]),
            URL_SAFE_NO_PAD.encode(&point[33..])
        );
        Self {
            point: point.to_vec(),
            kid: URL_SAFE_NO_PAD.encode(Sha256::digest(jwk)),
        }
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.point)
            .verify(input, signature)
            .map_err(|_| anyhow::anyhow!("signature does not verify with key {}", self.kid))
    }
}

/// The feed's keys, each on its own YubiKey; the first one not retired signs new drafts.
#[derive(Clone)]
pub struct Keys(Vec<Key>);

impl Keys {
    pub fn read(paths: &[PathBuf]) -> Result<Self> {
        Self::new(paths.iter().map(|p| Key::read(p)).collect::<Result<_>>()?)
    }

    pub fn new(keys: Vec<Key>) -> Result<Self> {
        ensure!(!keys.is_empty(), "no feed key given");
        let mut seen = HashSet::with_capacity(keys.len());
        ensure!(
            keys.iter().all(|k| seen.insert(k.kid.as_str())),
            "a feed key is given twice"
        );
        Ok(Self(keys))
    }

    pub fn kids(&self) -> Vec<String> {
        self.0.iter().map(|k| k.kid.clone()).collect()
    }

    fn get(&self, kid: &str) -> Option<&Key> {
        self.0.iter().find(|k| k.kid == kid)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// An entry's place in the feed; part of the signed claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub seq: u64,
    /// SHA-256 (hex) of the previous entry's compact JWS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrects: Option<Correction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retires: Option<Retirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correction {
    pub seq: u64,
    pub reason: String,
}

/// From this entry on, entries signed by `kid` are refused; it carries no verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retirement {
    pub kid: String,
    pub reason: String,
}

#[derive(Serialize)]
struct RetireEar {
    eat_profile: &'static str,
    iat: u64,
    ear_verifier_id: VerifierId,
    sr_feed: Link,
}

#[derive(Serialize)]
struct Ear<'a, S: Serialize> {
    eat_profile: &'static str,
    iat: u64,
    exp: u64,
    ear_verifier_id: VerifierId,
    ear_status: Tier,
    submods: BTreeMap<String, Appraisal<'a>>,
    sr_feed: Link,
    sr_scope: S,
}

#[derive(Serialize)]
struct VerifierId {
    developer: &'static str,
    build: &'static str,
}

#[derive(Serialize)]
struct Appraisal<'a> {
    ear_status: Tier,
    ear_appraisal_policy_ids: [&'static str; 1],
    eat_nonce: &'a str,
    ear_attester_claims: &'a Facts,
    ear_verifier_claims: VerifierClaims<'a>,
}

#[derive(Serialize)]
struct VerifierClaims<'a> {
    fetched_at: u64,
    /// The key of the client's connection, which the gate pins; absent for a machine behind the gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_spki_sha256: Option<&'a str>,
    /// The TLS key a machine behind the gateway binds in its own report; never pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    attested_tls_spki_sha256: Option<&'a str>,
    checks: &'a [Check],
}

#[derive(Serialize)]
struct Scope<'a> {
    host: &'a str,
    /// Sweeps and report fetches of the last 24 hours.
    sweeps: usize,
    tries: u32,
    machines: usize,
    not_reviewed: [&'a str; 2],
}

/// A route through the gateway: `host` names it, `connect` is where the client connects.
#[derive(Serialize)]
struct GatewayScope<'a> {
    host: String,
    connect: &'a str,
    model: &'a str,
    /// The gateway machine and each candidate.
    machines: usize,
    route: &'a [Check],
    not_reviewed: [&'a str; 3],
}

/// The signed claims a feed check reads; everything else in an entry is for its consumers.
#[derive(Debug, Deserialize)]
struct Head {
    eat_profile: String,
    iat: u64,
    exp: Option<u64>,
    ear_status: Option<Tier>,
    #[serde(default)]
    submods: BTreeMap<String, MachineRef>,
    sr_feed: Link,
    sr_scope: Option<HostOnly>,
}

#[derive(Debug)]
enum Body {
    Verdict(Verdict),
    Retire(Retirement),
}

#[derive(Debug)]
struct Verdict {
    host: String,
    status: Tier,
    exp: u64,
    submods: BTreeMap<String, MachineRef>,
}

impl Head {
    /// A retirement carries no verdict; every other entry carries a host, status and expiry.
    fn split(self) -> Result<(Link, Body)> {
        let Head {
            iat,
            exp,
            ear_status,
            submods,
            mut sr_feed,
            sr_scope,
            ..
        } = self;
        if let Some(retirement) = sr_feed.retires.take() {
            ensure!(
                exp.is_none()
                    && ear_status.is_none()
                    && sr_scope.is_none()
                    && submods.is_empty()
                    && sr_feed.corrects.is_none(),
                "a retirement carries no verdict"
            );
            return Ok((sr_feed, Body::Retire(retirement)));
        }
        let (Some(exp), Some(status), Some(scope)) = (exp, ear_status, sr_scope) else {
            bail!("a verdict needs exp, ear_status and sr_scope");
        };
        ensure!(
            sr_feed.corrects.is_some() || iat <= exp,
            "the entry expires before it is issued"
        );
        let verdict = Verdict {
            host: scope.host,
            status,
            exp,
            submods,
        };
        Ok((sr_feed, Body::Verdict(verdict)))
    }
}

#[derive(Debug, Deserialize)]
struct HostOnly {
    host: String,
}

#[derive(Debug, Deserialize)]
struct MachineRef {
    ear_status: Tier,
    ear_attester_claims: SignerOnly,
    ear_verifier_claims: TlsOnly,
}

#[derive(Debug, Deserialize)]
struct SignerOnly {
    signing_key: String,
}

#[derive(Debug, Deserialize)]
struct TlsOnly {
    #[serde(default)]
    tls_spki_sha256: Option<String>,
    checks: Vec<CheckRef>,
}

#[derive(Debug, Deserialize)]
struct CheckRef {
    id: String,
    status: Status,
}

/// Checks a candidate's key must pass before a client encrypts to it.
const MODEL_KEY_CHECKS: [&str; 2] = ["signer_bound", "reached_directly"];

impl MachineRef {
    /// The Ed25519 key of a gateway candidate whose binding and direct match passed.
    fn model_key(&self, label: &str) -> Option<ModelKey> {
        if !label.starts_with("candidate/") {
            return None;
        }
        let passed = MODEL_KEY_CHECKS.iter().all(|id| {
            self.ear_verifier_claims
                .checks
                .iter()
                .any(|c| c.id == *id && c.status == Status::Pass)
        });
        let key = self
            .ear_attester_claims
            .signing_key
            .strip_prefix("ed25519:")?;
        passed.then(|| ModelKey {
            key: key.to_ascii_lowercase(),
            status: self.ear_status,
        })
    }
}

struct Stored {
    jws: String,
    link: Link,
    body: Body,
}

/// Entries `000001.jwt`, `000002.jwt`, … from a directory, or as the mirror holds them; each verified on open.
pub struct Feed {
    dir: Option<PathBuf>,
    keys: Keys,
    /// Retired key ids, with the entry that retired each.
    retired: HashMap<String, u64>,
    entries: Vec<Stored>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub entries: usize,
    pub head: Option<HeadRef>,
    pub keys: Vec<KeyState>,
    /// Per host, the latest verdict and whether a later entry corrected it.
    pub current: Vec<Current>,
}

#[derive(Debug, Serialize)]
pub struct KeyState {
    pub kid: String,
    pub retired_by: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HeadRef {
    pub seq: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Current {
    pub host: String,
    pub seq: u64,
    pub status: Tier,
    pub exp: u64,
    pub expired: bool,
    pub corrected_by: Option<u64>,
    /// SHA-256 of the TLS key of each machine the verdict reviewed.
    pub tls_keys: Vec<String>,
    /// For a gateway route, the model keys a request may be encrypted to.
    pub model_keys: Vec<ModelKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelKey {
    /// Ed25519 public key, in hex.
    pub key: String,
    /// The candidate's own status.
    pub status: Tier,
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn b64_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?))
}

fn parts(jws: &str) -> Result<(&str, &str, Option<&str>)> {
    let mut split = jws.split('.');
    let (Some(header), Some(payload), signature, None) =
        (split.next(), split.next(), split.next(), split.next())
    else {
        bail!("not a compact JWS");
    };
    Ok((header, payload, signature))
}

fn decode<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T> {
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?)
}

/// The key id and claims of a signing input or entry.
fn open_claims(header: &str, payload: &str) -> Result<(String, Head)> {
    let header: Header = decode(header).context("entry header")?;
    ensure!(header.alg == ALG, "algorithm {} is not {ALG}", header.alg);
    let head: Head = decode(payload).context("entry claims")?;
    ensure!(head.eat_profile == PROFILE, "profile {}", head.eat_profile);
    Ok((header.kid, head))
}

fn entry_path(dir: &Path, seq: u64, ext: &str) -> PathBuf {
    dir.join(format!("{seq:06}.{ext}"))
}

/// The `.jwt` file names in `dir`, sorted; none if `dir` does not exist yet.
fn entry_names(dir: &Path) -> Result<Vec<String>> {
    let read = match std::fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut names = Vec::new();
    for entry in read {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".jwt") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

impl Feed {
    /// Verifies every entry: signature by a key not yet retired, sequence without gaps,
    /// previous-entry hash, corrections and retirements.
    pub fn open(dir: &Path, keys: Keys) -> Result<Self> {
        let names = entry_names(dir)?;
        let mut jws = Vec::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            ensure!(
                *name == format!("{:06}.jwt", i + 1),
                "entry {name} out of sequence"
            );
            jws.push(std::fs::read_to_string(dir.join(name))?.trim().to_owned());
        }
        Self::verified(Some(dir.to_owned()), jws, keys)
    }

    /// The same checks on entries held in memory, as read from the mirror.
    pub fn from_entries(jws: Vec<String>, keys: Keys) -> Result<Self> {
        Self::verified(None, jws, keys)
    }

    fn verified(dir: Option<PathBuf>, all: Vec<String>, keys: Keys) -> Result<Self> {
        let mut feed = Self {
            dir,
            keys,
            retired: HashMap::new(),
            entries: Vec::with_capacity(all.len()),
        };
        for jws in all {
            let name = format!("{:06}", feed.entries.len() + 1);
            let stored = feed
                .check_signed(jws)
                .with_context(|| format!("entry {name}"))?;
            feed.push(stored);
        }
        Ok(feed)
    }

    fn check_signed(&self, jws: String) -> Result<Stored> {
        let (header, payload, signature) = parts(&jws)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature.context("entry is unsigned")?)
            .context("signature is not base64url")?;
        ensure!(
            signature.len() == 64 && signature[32..] <= HALF_N[..],
            "signature is not low-S, so the mirror would refuse it"
        );
        let (key, link, body) = self.check_next(header, payload)?;
        key.verify(format!("{header}.{payload}").as_bytes(), &signature)?;
        Ok(Stored { jws, link, body })
    }

    /// The signer and contents of a signing input, checked as the feed's next entry.
    fn check_next(&self, header: &str, payload: &str) -> Result<(&Key, Link, Body)> {
        let (kid, head) = open_claims(header, payload)?;
        let key = self.signer(&kid)?;
        let (link, body) = head.split()?;
        let (seq, prev) = self.link_after();
        ensure!(
            (link.seq, &link.prev) == (seq, &prev),
            "entry {} does not follow entry {}",
            link.seq,
            seq - 1
        );
        match (&body, &link.corrects) {
            (Body::Retire(r), _) => self.retirable(&r.kid, &kid)?,
            (Body::Verdict(v), Some(c)) => {
                ensure!(c.seq < seq, "entry {seq} corrects a later entry");
                ensure!(
                    self.verdict_at(c.seq)?.host == v.host,
                    "a correction must name an entry of the same host"
                );
            }
            (Body::Verdict(_), None) => {}
        }
        Ok((key, link, body))
    }

    fn signer(&self, kid: &str) -> Result<&Key> {
        let key = self
            .keys
            .get(kid)
            .with_context(|| format!("signed by key {kid}, not one of the feed's keys"))?;
        if let Some(seq) = self.retired.get(kid) {
            bail!("signed by key {kid}, retired by entry {seq}");
        }
        Ok(key)
    }

    /// A key may be retired by another of the feed's keys, once, so one key always remains.
    fn retirable(&self, kid: &str, signer: &str) -> Result<()> {
        ensure!(
            self.keys.get(kid).is_some(),
            "retires key {kid}, not one of the feed's keys"
        );
        ensure!(kid != signer, "a key cannot retire itself");
        if let Some(seq) = self.retired.get(kid) {
            bail!("key {kid} was already retired by entry {seq}");
        }
        Ok(())
    }

    fn push(&mut self, stored: Stored) {
        if let Body::Retire(r) = &stored.body {
            self.retired.insert(r.kid.clone(), stored.link.seq);
        }
        self.entries.push(stored);
    }

    fn verdict_at(&self, seq: u64) -> Result<&Verdict> {
        let entry = seq
            .checked_sub(1)
            .and_then(|i| self.entries.get(usize::try_from(i).ok()?))
            .with_context(|| format!("no entry {seq}"))?;
        match &entry.body {
            Body::Verdict(v) => Ok(v),
            Body::Retire(_) => bail!("entry {seq} retires a key and holds no verdict"),
        }
    }

    /// The key that signs the next draft: the first given that is not retired and not `retiring`.
    fn next_signer(&self, retiring: Option<&str>) -> Result<&Key> {
        self.keys
            .0
            .iter()
            .find(|k| !self.retired.contains_key(&k.kid) && Some(k.kid.as_str()) != retiring)
            .context("no feed key left to sign with")
    }

    pub fn kids(&self) -> Vec<String> {
        self.keys.kids()
    }

    fn dir(&self) -> Result<&Path> {
        self.dir
            .as_deref()
            .context("this feed was read from the mirror and has no directory")
    }

    fn link_after(&self) -> (u64, Option<String>) {
        (
            self.entries.len() as u64 + 1,
            self.entries.last().map(|e| sha256_hex(&e.jws)),
        )
    }

    fn next_link(&self) -> Link {
        let (seq, prev) = self.link_after();
        Link {
            seq,
            prev,
            corrects: None,
            retires: None,
        }
    }

    /// EAR claims for one review: one submod per machine, the worst machine's tier overall.
    pub fn verdict(&self, sweep: &Sweep, reviewed: &[(Bundle, Review)], now: u64) -> Result<Value> {
        let oldest = reviewed
            .iter()
            .map(|(b, _)| b.fetched_at)
            .min()
            .context("no machine reviewed")?;
        let exp = oldest + LIFETIME_SECS;
        ensure!(exp > now, "evidence is older than {LIFETIME_SECS} seconds");
        let (sweeps, tries) = sweep.recent(now);
        let mut submods = BTreeMap::new();
        for (bundle, review) in reviewed {
            ensure!(
                bundle.fresh(now),
                "a machine was fetched {MAX_AGE_SECS} seconds ago or earlier"
            );
            ensure!(
                review.host == sweep.host,
                "a bundle is from {}, not {}",
                review.host,
                sweep.host
            );
            let tls = &bundle.peer_spki_sha256;
            let label = format!(
                "{}/{}",
                review.facts.instance_id,
                tls.get(..16).unwrap_or(tls)
            );
            let appraisal = Appraisal {
                ear_status: review.tier,
                ear_appraisal_policy_ids: [POLICY],
                eat_nonce: &bundle.nonce,
                ear_attester_claims: &review.facts,
                ear_verifier_claims: VerifierClaims {
                    fetched_at: bundle.fetched_at,
                    tls_spki_sha256: Some(tls),
                    attested_tls_spki_sha256: None,
                    checks: &review.checks,
                },
            };
            ensure!(
                submods.insert(label.clone(), appraisal).is_none(),
                "machine {label} reviewed twice"
            );
        }
        let ear = Ear {
            eat_profile: PROFILE,
            iat: now,
            exp,
            ear_verifier_id: VerifierId {
                developer: DEVELOPER,
                build: BUILD,
            },
            ear_status: Tier::worst(reviewed.iter().map(|(_, r)| r.tier)),
            submods,
            sr_feed: self.next_link(),
            sr_scope: Scope {
                host: &sweep.host,
                sweeps,
                tries,
                machines: reviewed.len(),
                not_reviewed: NOT_REVIEWED,
            },
        };
        Ok(serde_json::to_value(ear)?)
    }

    /// EAR claims for one gateway answer: a submod for the gateway machine, whose TLS key the gate
    /// may pin, and one per candidate, whose attested key is only recorded.
    pub fn gateway_verdict(&self, review: &gateway::Review, now: u64) -> Result<Value> {
        let exp = review.fetched_at + LIFETIME_SECS;
        ensure!(exp > now, "evidence is older than {LIFETIME_SECS} seconds");
        ensure!(
            review.fetched_at.saturating_add(MAX_AGE_SECS) > now,
            "the gateway answer was fetched {MAX_AGE_SECS} seconds ago or earlier"
        );
        let label = |role: &str, machine: &Review, key: Option<&str>| {
            let key = key.unwrap_or("none");
            format!(
                "{role}/{}/{}",
                machine.facts.instance_id,
                key.get(..16).unwrap_or(key)
            )
        };
        let mut submods = BTreeMap::new();
        submods.insert(
            label("gateway", &review.gateway, Some(&review.peer_spki_sha256)),
            routed(review, &review.gateway, true),
        );
        for candidate in &review.candidates {
            let name = label("candidate", candidate, candidate.facts.tls_key.as_deref());
            ensure!(
                submods
                    .insert(name.clone(), routed(review, candidate, false))
                    .is_none(),
                "machine {name} reviewed twice"
            );
        }
        let ear = Ear {
            eat_profile: PROFILE,
            iat: now,
            exp,
            ear_verifier_id: VerifierId {
                developer: DEVELOPER,
                build: BUILD,
            },
            ear_status: review.tier,
            submods,
            sr_feed: self.next_link(),
            sr_scope: GatewayScope {
                host: format!("{}/{}", review.host, review.model),
                connect: &review.host,
                model: &review.model,
                machines: 1 + review.candidates.len(),
                route: &review.route,
                not_reviewed: GATEWAY_NOT_REVIEWED,
            },
        };
        Ok(serde_json::to_value(ear)?)
    }

    /// Restates entry `seq` with `status` for it and every machine in it; it keeps the entry's expiry.
    pub fn correction(&self, seq: u64, status: Tier, reason: &str, now: u64) -> Result<Value> {
        self.verdict_at(seq)?;
        ensure!(!reason.trim().is_empty(), "a correction needs a reason");
        let target = &self.entries[(seq - 1) as usize];
        let (_, payload, _) = parts(&target.jws)?;
        let mut claims: Value = decode(payload)?;
        let status = serde_json::to_value(status)?;
        if let Some(submods) = claims["submods"].as_object_mut() {
            for appraisal in submods.values_mut() {
                appraisal["ear_status"] = status.clone();
            }
        }
        claims["ear_status"] = status;
        claims["iat"] = now.into();
        claims["sr_feed"] = serde_json::to_value(Link {
            corrects: Some(Correction {
                seq,
                reason: reason.to_owned(),
            }),
            ..self.next_link()
        })?;
        Ok(claims)
    }

    /// An entry that retires key `kid`; another key signs it.
    pub fn retirement(&self, kid: &str, reason: &str, now: u64) -> Result<Value> {
        ensure!(!reason.trim().is_empty(), "a retirement needs a reason");
        let ear = RetireEar {
            eat_profile: PROFILE,
            iat: now,
            ear_verifier_id: VerifierId {
                developer: DEVELOPER,
                build: BUILD,
            },
            sr_feed: Link {
                retires: Some(Retirement {
                    kid: kid.to_owned(),
                    reason: reason.to_owned(),
                }),
                ..self.next_link()
            },
        };
        Ok(serde_json::to_value(ear)?)
    }

    /// Writes the unsigned signing input `BASE64URL(header).BASE64URL(claims)` for the user to sign,
    /// naming the key that must sign it.
    pub fn write_draft(&self, claims: &Value) -> Result<Drafted> {
        let retiring = claims["sr_feed"]["retires"]["kid"].as_str();
        let kid = self.next_signer(retiring)?.kid.clone();
        let header = Header {
            alg: ALG.into(),
            typ: "JWT".into(),
            kid: kid.clone(),
        };
        let (header, payload) = (b64_json(&header)?, b64_json(claims)?);
        let (_, link, _) = self
            .check_next(&header, &payload)
            .context("the draft is not a valid next entry")?;
        let dir = self.dir()?;
        std::fs::create_dir_all(dir)?;
        let path = entry_path(dir, link.seq, "draft");
        std::fs::write(&path, format!("{header}.{payload}"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Drafted { path, kid })
    }

    /// Joins a draft and the YubiKey's signature (DER or raw r‖s) into the next entry, once both verify.
    pub fn seal(&self, draft: &Path, signature: &Path) -> Result<PathBuf> {
        let input = std::fs::read_to_string(draft)
            .with_context(|| format!("reading {}", draft.display()))?;
        let (header, payload, rest) = parts(input.trim())?;
        ensure!(rest.is_none(), "the draft is already signed");
        let (key, link, _) = self
            .check_next(header, payload)
            .with_context(|| format!("draft {}", draft.display()))?;
        let raw =
            std::fs::read(signature).with_context(|| format!("reading {}", signature.display()))?;
        let fixed = low_s(match raw.len() {
            64 => raw.try_into().expect("64 bytes"),
            _ => der_to_fixed(&raw)?,
        });
        let signing_input = format!("{header}.{payload}");
        key.verify(signing_input.as_bytes(), &fixed)?;
        let jws = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(fixed));
        let path = entry_path(self.dir()?, link.seq, "jwt");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, jws.as_bytes()))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    /// SHA-256 (hex) of each entry's compact JWS, in sequence order.
    pub fn hashes(&self) -> Vec<String> {
        self.entries.iter().map(|e| sha256_hex(&e.jws)).collect()
    }

    pub fn entry_file(&self, seq: u64) -> Result<PathBuf> {
        Ok(entry_path(self.dir()?, seq, "jwt"))
    }

    pub fn summary(&self, now: u64) -> Summary {
        let mut current: BTreeMap<&str, Current> = BTreeMap::new();
        let mut host_of: HashMap<u64, &str> = HashMap::with_capacity(self.entries.len());
        for Stored { link, body, .. } in &self.entries {
            let Body::Verdict(v) = body else {
                continue;
            };
            let host = v.host.as_str();
            host_of.insert(link.seq, host);
            let Some(c) = &link.corrects else {
                current.insert(
                    host,
                    Current {
                        host: host.to_owned(),
                        seq: link.seq,
                        status: v.status,
                        exp: v.exp,
                        expired: v.exp <= now,
                        corrected_by: None,
                        tls_keys: v
                            .submods
                            .values()
                            .filter_map(|m| m.ear_verifier_claims.tls_spki_sha256.clone())
                            .collect(),
                        model_keys: v
                            .submods
                            .iter()
                            .filter_map(|(label, m)| m.model_key(label))
                            .collect(),
                    },
                );
                continue;
            };
            let Some(entry) = host_of.get(&c.seq).and_then(|h| current.get_mut(h)) else {
                continue;
            };
            if entry.seq == c.seq {
                entry.status = v.status;
                entry.corrected_by = Some(link.seq);
            }
        }
        Summary {
            entries: self.entries.len(),
            head: self.entries.last().map(|e| HeadRef {
                seq: e.link.seq,
                sha256: sha256_hex(&e.jws),
            }),
            keys: self
                .keys
                .0
                .iter()
                .map(|k| KeyState {
                    kid: k.kid.clone(),
                    retired_by: self.retired.get(&k.kid).copied(),
                })
                .collect(),
            current: current.into_values().collect(),
        }
    }
}

/// A draft on disk, and the key whose YubiKey must sign it.
pub struct Drafted {
    pub path: PathBuf,
    pub kid: String,
}

/// One machine of a gateway answer; only the gateway's key is on the client's connection.
fn routed<'a>(review: &'a gateway::Review, machine: &'a Review, pinned: bool) -> Appraisal<'a> {
    let key = if pinned {
        Some(review.peer_spki_sha256.as_str())
    } else {
        machine.facts.tls_key.as_deref()
    };
    Appraisal {
        ear_status: machine.tier,
        ear_appraisal_policy_ids: [POLICY],
        eat_nonce: &review.nonce,
        ear_attester_claims: &machine.facts,
        ear_verifier_claims: VerifierClaims {
            fetched_at: review.fetched_at,
            tls_spki_sha256: key.filter(|_| pinned),
            attested_tls_spki_sha256: key.filter(|_| !pinned),
            checks: &machine.checks,
        },
    }
}

fn der_tlv(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let [t, len, rest @ ..] = bytes else {
        bail!("signature DER is truncated");
    };
    let len = usize::from(*len);
    ensure!(
        *t == tag && len < 0x80 && rest.len() >= len,
        "signature is not DER ECDSA"
    );
    Ok(rest.split_at(len))
}

fn put_scalar(out: &mut [u8], int: &[u8]) -> Result<()> {
    let start = int.iter().position(|&b| b != 0).unwrap_or(int.len());
    let int = &int[start..];
    ensure!(
        int.len() <= out.len(),
        "signature scalar too long for P-256"
    );
    let start = out.len() - int.len();
    out[start..].copy_from_slice(int);
    Ok(())
}

/// ECDSA `SEQUENCE { INTEGER r, INTEGER s }` to JWS's fixed 32-byte `r ‖ s`.
fn der_to_fixed(der: &[u8]) -> Result<[u8; 64]> {
    let (body, rest) = der_tlv(der, 0x30)?;
    ensure!(rest.is_empty(), "bytes after the signature");
    let (r, rest) = der_tlv(body, 0x02)?;
    let (s, rest) = der_tlv(rest, 0x02)?;
    ensure!(rest.is_empty(), "bytes after s");
    let mut fixed = [0u8; 64];
    put_scalar(&mut fixed[..32], r)?;
    put_scalar(&mut fixed[32..], s)?;
    Ok(fixed)
}

/// The same signature with `s` replaced by `N - s` when `s > N / 2`; both verify.
fn low_s(mut fixed: [u8; 64]) -> [u8; 64] {
    if fixed[32..] <= HALF_N[..] {
        return fixed;
    }
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(N[i]) - i16::from(fixed[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        fixed[32 + i] = d.rem_euclid(256) as u8;
    }
    fixed
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;
    use crate::bundle::{Run, sample};
    use crate::review::Facts;
    use crate::verdict::{Check, Status};

    /// A made-up review of a made-up machine; the feed signs whatever the review says.
    fn reviewed(bundle: Bundle) -> (Bundle, Review) {
        let review = Review {
            watcher: "sealed-review-watcher/test",
            host: bundle.host.clone(),
            fetched_at: bundle.fetched_at,
            tier: Tier::None,
            facts: Facts {
                app_id: "sample-app".into(),
                instance_id: "instance-1".into(),
                app_name: "sample".into(),
                image: None,
                os_image_hash: "00".repeat(32),
                compose_hash: "00".repeat(32),
                signing_key: "ecdsa:0x01".into(),
                tls_key: None,
                mrtd: None,
                rtmr: None,
                ohttp: None,
                kms: None,
                key_provider_id: None,
            },
            checks: vec![Check::new(
                2,
                "quote_signature",
                Status::Unknown,
                "no quote",
            )],
        };
        (bundle, review)
    }

    struct Signer {
        pair: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl Signer {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self { pair, rng }
        }

        fn key(&self) -> Key {
            let der = [SPKI_P256.as_slice(), self.pair.public_key().as_ref()].concat();
            let pem = format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                STANDARD.encode(der)
            );
            Key::from_pem(&pem).unwrap()
        }

        /// What the YubiKey returns: a DER signature over SHA-256 of the draft.
        fn sign(&self, draft: &Path, out: &Path) {
            let input = std::fs::read(draft).unwrap();
            let sig = self.pair.sign(&self.rng, &input).unwrap();
            std::fs::write(out, sig.as_ref()).unwrap();
        }
    }

    struct Fixture {
        dir: PathBuf,
        /// Key A, then key B.
        signers: [Signer; 2],
        keys: Keys,
        sweep: Sweep,
        reviewed: Vec<(Bundle, Review)>,
        now: u64,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("sr-feed-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let bundle = sample("instance-1", &"11".repeat(32), 1_800_000_000);
            let sweep = Sweep {
                host: bundle.host.clone(),
                runs: vec![Run {
                    at: bundle.fetched_at,
                    tries: 5,
                }],
                bundles: vec!["machine-1.json".into()],
            };
            let now = bundle.fetched_at + 60;
            let signers = [Signer::new(), Signer::new()];
            Self {
                dir,
                keys: Keys::new(signers.iter().map(Signer::key).collect()).unwrap(),
                signers,
                sweep,
                reviewed: vec![reviewed(bundle)],
                now,
            }
        }

        fn feed(&self) -> Result<Feed> {
            Feed::open(&self.dir, self.keys.clone())
        }

        fn signer(&self, kid: &str) -> &Signer {
            self.signers.iter().find(|s| s.key().kid == kid).unwrap()
        }

        fn kid(&self, i: usize) -> String {
            self.signers[i].key().kid
        }

        fn append(&self, claims: &Value) -> PathBuf {
            let feed = self.feed().unwrap();
            let drafted = feed.write_draft(claims).unwrap();
            let sig = drafted.path.with_extension("sig");
            self.signer(&drafted.kid).sign(&drafted.path, &sig);
            feed.seal(&drafted.path, &sig).unwrap()
        }

        fn verdict(&self) -> Value {
            self.feed()
                .unwrap()
                .verdict(&self.sweep, &self.reviewed, self.now)
                .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn gateway_review(fetched_at: u64) -> gateway::Review {
        let machine = |instance: &str, tls: Option<String>| {
            let (_, mut review) = reviewed(sample(instance, "", fetched_at));
            review.facts.instance_id = instance.into();
            review.facts.tls_key = tls;
            review.facts.signing_key = format!("ed25519:{}", instance.len().to_string().repeat(64));
            review.tier = Tier::Warning;
            review.checks = ["signer_bound", "reached_directly"]
                .map(|id| Check::new(5, id, Status::Pass, "test"))
                .into();
            review
        };
        let mut unmatched = machine("model-two", Some("dd".repeat(32)));
        unmatched.checks[1].status = Status::Unknown;
        gateway::Review {
            watcher: "sealed-review-watcher/test",
            host: "cloud-api.near.ai".into(),
            model: "z-ai/glm-5.3-flash".into(),
            fetched_at,
            nonce: "00".repeat(32),
            peer_spki_sha256: "aa".repeat(32),
            tier: Tier::Warning,
            route: Vec::new(),
            gateway: machine("gateway-1", Some("aa".repeat(32))),
            candidates: vec![machine("model-1", Some("cc".repeat(32))), unmatched],
        }
    }

    #[test]
    fn a_gateway_entry_pins_only_the_gateway() {
        let f = Fixture::new("gateway");
        let claims = f
            .feed()
            .unwrap()
            .gateway_verdict(&gateway_review(f.now - 60), f.now)
            .unwrap();
        assert_eq!(claims["sr_scope"]["connect"], "cloud-api.near.ai");
        f.append(&claims);
        let summary = f.feed().unwrap().summary(f.now);
        let current = &summary.current[0];
        assert_eq!(current.host, "cloud-api.near.ai/z-ai/glm-5.3-flash");
        assert_eq!(current.status, Tier::Warning);
        assert_eq!(current.tls_keys, vec!["aa".repeat(32)]);
        assert_eq!(
            current.model_keys,
            [ModelKey {
                key: "7".repeat(64),
                status: Tier::Warning,
            }],
            "only the candidate whose key is bound and reached directly"
        );
    }

    #[test]
    fn an_old_gateway_answer_is_refused() {
        let f = Fixture::new("gateway-old");
        let feed = f.feed().unwrap();
        assert!(
            feed.gateway_verdict(&gateway_review(f.now - MAX_AGE_SECS), f.now)
                .is_err()
        );
    }

    #[test]
    fn entries_chain_and_verify() {
        let f = Fixture::new("chain");
        let first = f.verdict();
        assert_eq!(first["submods"].as_object().unwrap().len(), 1);
        assert_eq!(first["sr_scope"]["tries"], 5);
        assert_eq!(first["sr_scope"]["sweeps"], 1);
        assert_eq!(first["exp"], f.reviewed[0].0.fetched_at + LIFETIME_SECS);
        let path = f.append(&first);
        let second = f.verdict();
        assert_eq!(second["sr_feed"]["seq"], 2);
        let jws = std::fs::read_to_string(path).unwrap();
        assert_eq!(second["sr_feed"]["prev"], sha256_hex(&jws));
        f.append(&second);

        let summary = f.feed().unwrap().summary(f.now);
        assert_eq!(summary.entries, 2);
        assert_eq!(summary.current.len(), 1);
        assert_eq!(summary.current[0].seq, 2);
        assert_eq!(summary.current[0].status, Tier::None);
        assert!(!summary.current[0].expired);
        assert_eq!(
            summary.current[0].tls_keys,
            [f.reviewed[0].0.peer_spki_sha256.clone()]
        );
        assert!(f.feed().unwrap().summary(f.now + LIFETIME_SECS).current[0].expired);

        let held: Vec<String> = (1..=2)
            .map(|seq| std::fs::read_to_string(entry_path(&f.dir, seq, "jwt")).unwrap())
            .collect();
        let mirrored = Feed::from_entries(held.clone(), f.keys.clone()).unwrap();
        assert_eq!(mirrored.hashes(), f.feed().unwrap().hashes());
        assert!(mirrored.entry_file(1).is_err());
        assert!(Feed::from_entries(held[1..].to_vec(), f.keys.clone()).is_err());
    }

    #[test]
    fn a_changed_entry_fails() {
        let f = Fixture::new("tamper");
        let path = f.append(&f.verdict());
        let jws = std::fs::read_to_string(&path).unwrap();
        let (header, payload, signature) = parts(&jws).unwrap();
        let mut claims: Value = decode(payload).unwrap();
        claims["ear_status"] = "affirming".into();
        let forged = format!(
            "{header}.{}.{}",
            b64_json(&claims).unwrap(),
            signature.unwrap()
        );
        std::fs::write(&path, forged).unwrap();
        assert!(f.feed().is_err());
    }

    #[test]
    fn a_removed_entry_breaks_the_chain() {
        let f = Fixture::new("gap");
        let first = f.append(&f.verdict());
        let second = f.append(&f.verdict());
        std::fs::remove_file(&first).unwrap();
        std::fs::rename(&second, &first).unwrap();
        let error = format!("{:#}", f.feed().err().unwrap());
        assert!(error.contains("does not follow"), "{error}");
    }

    #[test]
    fn another_key_is_refused() {
        let f = Fixture::new("key");
        let feed = f.feed().unwrap();
        let draft = feed.write_draft(&f.verdict()).unwrap().path;
        let sig = draft.with_extension("sig");
        Signer::new().sign(&draft, &sig);
        assert!(feed.seal(&draft, &sig).is_err());
        f.signers[1].sign(&draft, &sig);
        assert!(
            feed.seal(&draft, &sig).is_err(),
            "key B signed a draft that names key A"
        );
    }

    #[test]
    fn a_stale_draft_is_refused() {
        let f = Fixture::new("stale");
        let feed = f.feed().unwrap();
        let draft = feed.write_draft(&f.verdict()).unwrap().path;
        let sig = draft.with_extension("sig");
        f.signers[0].sign(&draft, &sig);
        let kept = std::fs::read(&draft).unwrap();
        feed.seal(&draft, &sig).unwrap();
        std::fs::write(&draft, kept).unwrap();
        assert!(f.feed().unwrap().seal(&draft, &sig).is_err());
    }

    #[test]
    fn old_evidence_is_refused() {
        let f = Fixture::new("old");
        let fetched = f.reviewed[0].0.fetched_at;
        let feed = f.feed().unwrap();
        assert!(
            feed.verdict(&f.sweep, &f.reviewed, fetched + MAX_AGE_SECS - 1)
                .is_ok()
        );
        assert!(
            feed.verdict(&f.sweep, &f.reviewed, fetched + MAX_AGE_SECS)
                .is_err()
        );
    }

    #[test]
    fn a_correction_replaces_the_status() {
        let f = Fixture::new("correct");
        f.append(&f.verdict());
        let claims = f
            .feed()
            .unwrap()
            .correction(1, Tier::Contraindicated, "wrong image", f.now)
            .unwrap();
        assert_eq!(claims["sr_feed"]["corrects"]["seq"], 1);
        f.append(&claims);
        let current = &f.feed().unwrap().summary(f.now).current[0];
        assert_eq!(
            (current.seq, current.status, current.corrected_by),
            (1, Tier::Contraindicated, Some(2))
        );
    }

    #[test]
    fn either_key_signs_until_one_is_retired() {
        let f = Fixture::new("retire");
        let (a, b) = (f.kid(0), f.kid(1));
        f.append(&f.verdict());
        let feed = f.feed().unwrap();
        assert_eq!(
            feed.write_draft(&f.verdict()).unwrap().kid,
            a,
            "key A signs first"
        );
        let claims = feed.retirement(&a, "YubiKey A lost", f.now).unwrap();
        assert_eq!(
            feed.write_draft(&claims).unwrap().kid,
            b,
            "the other key retires A"
        );
        f.append(&claims);
        f.append(&f.verdict());

        let feed = f.feed().unwrap();
        let summary = feed.summary(f.now);
        assert_eq!(summary.entries, 3);
        assert_eq!(summary.current[0].seq, 3);
        let retired: Vec<_> = summary.keys.iter().map(|k| k.retired_by).collect();
        assert_eq!(retired, [Some(2), None]);
        let last = feed.retirement(&b, "last key", f.now).unwrap();
        let error = format!("{:#}", feed.write_draft(&last).err().unwrap());
        assert!(error.contains("no feed key left"), "{error}");
        assert!(
            feed.correction(2, Tier::None, "not a verdict", f.now)
                .is_err()
        );
    }

    #[test]
    fn a_retired_key_is_refused() {
        let f = Fixture::new("retired");
        let a = f.kid(0);
        let feed = f.feed().unwrap();
        let early = feed.write_draft(&f.verdict()).unwrap();
        assert_eq!(early.kid, a);
        f.append(&feed.retirement(&a, "rotated", f.now).unwrap());

        let feed = f.feed().unwrap();
        let claims = f.verdict();
        let header = b64_json(&Header {
            alg: ALG.into(),
            typ: "JWT".into(),
            kid: a.clone(),
        })
        .unwrap();
        let draft = f.dir.join("by-a.draft");
        std::fs::write(&draft, format!("{header}.{}", b64_json(&claims).unwrap())).unwrap();
        let sig = draft.with_extension("sig");
        f.signers[0].sign(&draft, &sig);
        let error = format!("{:#}", feed.seal(&draft, &sig).err().unwrap());
        assert!(error.contains("retired by entry 1"), "{error}");
    }

    #[test]
    fn a_key_cannot_retire_itself_or_a_stranger() {
        let f = Fixture::new("retire-self");
        let a = f.kid(0);
        let feed = f.feed().unwrap();
        let mut claims = feed.retirement(&a, "self", f.now).unwrap();
        let header = |kid: &str| {
            b64_json(&Header {
                alg: ALG.into(),
                typ: "JWT".into(),
                kid: kid.into(),
            })
            .unwrap()
        };
        let payload = b64_json(&claims).unwrap();
        let error = format!(
            "{:#}",
            feed.check_next(&header(&a), &payload).err().unwrap()
        );
        assert!(error.contains("cannot retire itself"), "{error}");
        claims["sr_feed"]["retires"]["kid"] = "stranger".into();
        let error = format!("{:#}", feed.write_draft(&claims).err().unwrap());
        assert!(error.contains("not one of the feed's keys"), "{error}");
        claims["sr_feed"]["retires"]["kid"] = f.kid(1).into();
        claims["ear_status"] = "affirming".into();
        let error = format!("{:#}", feed.write_draft(&claims).err().unwrap());
        assert!(error.contains("carries no verdict"), "{error}");
    }

    #[test]
    fn keys_are_distinct() {
        let key = Signer::new().key();
        assert!(Keys::new(vec![key.clone(), key]).is_err());
        assert!(Keys::new(Vec::new()).is_err());
    }

    #[test]
    fn signatures_are_low_s() {
        let f = Fixture::new("low-s");
        let path = f.append(&f.verdict());
        let jws = std::fs::read_to_string(&path).unwrap();
        let (header, payload, signature) = parts(&jws).unwrap();
        let sealed: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature.unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(sealed[32..] <= HALF_N[..]);
        let mut twin = sealed;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(sealed[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            twin[32 + i] = d.rem_euclid(256) as u8;
        }
        assert_eq!(low_s(twin), sealed);
        f.signers[0]
            .key()
            .verify(format!("{header}.{payload}").as_bytes(), &twin)
            .unwrap();
        let high = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(twin));
        std::fs::write(&path, high).unwrap();
        let error = format!("{:#}", f.feed().err().unwrap());
        assert!(error.contains("low-S"), "{error}");
    }

    #[test]
    fn der_signatures_convert() {
        let mut der = vec![0x30, 0x45, 0x02, 0x21, 0x00];
        der.extend([0xaa; 32]);
        der.extend([0x02, 0x20]);
        der.extend([0x00; 1]);
        der.extend([0x01; 31]);
        let fixed = der_to_fixed(&der).unwrap();
        assert_eq!(fixed[..32], [0xaa; 32]);
        assert_eq!(fixed[32], 0);
        assert_eq!(fixed[33..], [0x01; 31]);
        assert!(der_to_fixed(&der[..10]).is_err());
        der.push(0);
        assert!(der_to_fixed(&der).is_err());
    }
}
