use std::path::Path;

use anyhow::{Context, Result, ensure};
use dcap_qvl::QuoteCollateralV3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::report::Report;

/// A machine's evidence enters a verdict for this long after it was fetched.
pub const MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// A machine counts as the same only if instance id, compose hash and the connection's TLS key all match.
pub type Machine = (String, String, String);

pub fn machine(report: &Report, peer_spki_sha256: &str) -> Machine {
    (
        report.info.instance_id.clone(),
        hex::encode(Sha256::digest(report.info.tcb_info.app_compose.as_bytes())),
        peer_spki_sha256.to_owned(),
    )
}

fn fresh(fetched_at: u64, now: u64) -> bool {
    fetched_at.saturating_add(MAX_AGE_SECS) > now
}

/// Everything one observation rests on, saved as fetched so the checks can be re-run offline.
#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub host: String,
    /// Unix seconds when the report and collateral were fetched; quotes are appraised at this time.
    pub fetched_at: u64,
    pub nonce: String,
    /// SHA-256 of the SubjectPublicKeyInfo of the certificate on the connection that returned the report.
    pub peer_spki_sha256: String,
    /// The report body exactly as received.
    pub report: String,
    pub collateral: Vec<Collateral>,
    #[serde(default)]
    pub gpu: Option<Gpu>,
    /// NEAR's endpoint registry as received during the sweep; absent if it could not be fetched.
    #[serde(default)]
    pub registry: Option<String>,
}

/// NRAS's answer to the report's GPU evidence, with the JWKS entries that sign it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Gpu {
    /// The NRAS response body exactly as received.
    pub response: Option<String>,
    pub keys: Vec<Jwk>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    /// Base64 DER certificates, leaf first.
    pub x5c: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Intel,
    Phala,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Standard,
    Early,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {
    pub source: Source,
    pub stream: Stream,
    pub data: Option<QuoteCollateralV3>,
    pub error: Option<String>,
}

/// One sweep's start time and report fetches, including those that reached a machine already seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub at: u64,
    pub tries: u32,
}

/// A host's fetch directory: the machines of the last 24 hours' sweeps, one bundle file each.
#[derive(Debug, Serialize, Deserialize)]
pub struct Sweep {
    pub host: String,
    pub runs: Vec<Run>,
    pub bundles: Vec<String>,
}

/// What a merge does with each machine already in the directory and each one just fetched.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Existing, not reached again, still fresh.
    pub keep: Vec<usize>,
    /// (existing, incoming): reached again, so the fresh bundle replaces the old one.
    pub replace: Vec<(usize, usize)>,
    /// Incoming machines not in the directory.
    pub add: Vec<usize>,
    /// Existing, not reached again, 24 hours old or older.
    pub drop: Vec<usize>,
}

pub fn plan(existing: &[(Machine, u64)], incoming: &[Machine], now: u64) -> Plan {
    let mut plan = Plan::default();
    let mut matched = vec![false; incoming.len()];
    for (i, (machine, fetched_at)) in existing.iter().enumerate() {
        match incoming.iter().position(|m| m == machine) {
            Some(j) => {
                matched[j] = true;
                plan.replace.push((i, j));
            }
            None if fresh(*fetched_at, now) => plan.keep.push(i),
            None => plan.drop.push(i),
        }
    }
    plan.add = (0..incoming.len()).filter(|&j| !matched[j]).collect();
    plan
}

#[derive(Debug)]
pub struct Merged {
    pub sweep: Sweep,
    pub plan: Plan,
}

impl Sweep {
    const FILE: &str = "sweep.json";

    /// Sweeps and report fetches of the last 24 hours.
    pub fn recent(&self, now: u64) -> (usize, u32) {
        self.runs
            .iter()
            .filter(|r| fresh(r.at, now))
            .fold((0, 0), |(sweeps, tries), r| (sweeps + 1, tries + r.tries))
    }

    /// Adds one sweep's bundles to `dir`: a machine reached again gets its new bundle under its old name,
    /// a new machine the next free name, and a machine 24 hours old or older is removed.
    pub fn merge(
        dir: &Path,
        host: &str,
        run: Run,
        incoming: &[Bundle],
        now: u64,
    ) -> Result<Merged> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let (old, existing) = match dir.join(Self::FILE).exists() {
            true => {
                let (sweep, bundles) = Self::read(dir)?;
                ensure!(
                    sweep.host == host,
                    "{} holds {}, not {host}",
                    dir.display(),
                    sweep.host
                );
                (Some(sweep), bundles)
            }
            false => (None, Vec::new()),
        };
        let identities = existing
            .iter()
            .map(|b| Ok((b.machine()?, b.fetched_at)))
            .collect::<Result<Vec<_>>>()?;
        let reached = incoming
            .iter()
            .map(Bundle::machine)
            .collect::<Result<Vec<_>>>()?;
        let plan = plan(&identities, &reached, now);
        let (old_names, old_runs) = old.map_or_else(Default::default, |s| (s.bundles, s.runs));

        let mut next = old_names
            .iter()
            .filter_map(|n| {
                n.strip_prefix("machine-")?
                    .strip_suffix(".json")?
                    .parse::<u32>()
                    .ok()
            })
            .max()
            .unwrap_or(0);
        let mut names = Vec::with_capacity(plan.keep.len() + plan.replace.len() + plan.add.len());
        for (i, name) in old_names.iter().enumerate() {
            if plan.keep.contains(&i) {
                names.push(name.clone());
            } else if let Some(&(_, j)) = plan.replace.iter().find(|(e, _)| *e == i) {
                incoming[j].write(&dir.join(name))?;
                names.push(name.clone());
            }
        }
        for &j in &plan.add {
            next += 1;
            let name = format!("machine-{next}.json");
            incoming[j].write(&dir.join(&name))?;
            names.push(name);
        }
        let mut runs: Vec<Run> = old_runs.into_iter().filter(|r| fresh(r.at, now)).collect();
        runs.push(run);
        let sweep = Self {
            host: host.to_owned(),
            runs,
            bundles: names,
        };
        std::fs::write(dir.join(Self::FILE), serde_json::to_string_pretty(&sweep)?)?;
        for &i in &plan.drop {
            std::fs::remove_file(dir.join(&old_names[i]))
                .with_context(|| format!("removing {}", old_names[i]))?;
        }
        Ok(Merged { sweep, plan })
    }

    pub fn read(dir: &Path) -> Result<(Self, Vec<Bundle>)> {
        let path = dir.join(Self::FILE);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let sweep: Self = serde_json::from_str(&text)?;
        let bundles = sweep
            .bundles
            .iter()
            .map(|name| {
                ensure!(
                    Path::new(name).file_name() == Some(name.as_ref()),
                    "bundle name {name} is not a plain file name"
                );
                let bundle = Bundle::read(&dir.join(name))?;
                ensure!(
                    bundle.host == sweep.host,
                    "{name} is from {}, not {}",
                    bundle.host,
                    sweep.host
                );
                Ok(bundle)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((sweep, bundles))
    }
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

    pub fn machine(&self) -> Result<Machine> {
        Ok(machine(
            &Report::parse(&self.report)?,
            &self.peer_spki_sha256,
        ))
    }

    /// Whether this evidence may still enter a verdict at `now`.
    pub fn fresh(&self, now: u64) -> bool {
        fresh(self.fetched_at, now)
    }

    pub fn collateral(&self, source: Source, stream: Stream) -> Option<&Collateral> {
        self.collateral
            .iter()
            .find(|c| c.source == source && c.stream == stream)
    }
}

/// A made-up bundle: a report with just the fields that identify a machine, and no evidence.
#[cfg(test)]
pub fn sample(instance_id: &str, peer_spki_sha256: &str, fetched_at: u64) -> Bundle {
    let report = serde_json::json!({
        "signing_address": "0x0000000000000000000000000000000000000001",
        "signing_algo": "ecdsa",
        "request_nonce": "00".repeat(32),
        "intel_quote": "",
        "info": {
            "app_id": "sample-app",
            "instance_id": instance_id,
            "app_name": "sample",
            "vm_config": "{}",
            "tcb_info": { "app_compose": "{\"name\":\"sample\"}", "event_log": [] },
        },
    });
    Bundle {
        host: "model.example".into(),
        fetched_at,
        nonce: "00".repeat(32),
        peer_spki_sha256: peer_spki_sha256.into(),
        report: report.to_string(),
        collateral: Vec::new(),
        gpu: None,
        registry: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 60 * 60;
    const T: u64 = 1_800_000_000;

    fn m(name: &str) -> Machine {
        (name.into(), "compose".into(), "tls".into())
    }

    #[test]
    fn machines_are_kept_replaced_added_and_dropped() {
        let now = 100 * HOUR;
        let existing = [
            (m("a"), now - HOUR),
            (m("b"), now - 30 * HOUR),
            (m("c"), now - 24 * HOUR),
            (m("d"), now - 2 * HOUR),
        ];
        let plan = plan(&existing, &[m("e"), m("d"), m("b")], now);
        assert_eq!(
            plan,
            Plan {
                keep: vec![0],
                replace: vec![(1, 2), (3, 1)],
                add: vec![0],
                drop: vec![2],
            }
        );
    }

    #[test]
    fn a_directory_accumulates() {
        let dir = std::env::temp_dir().join(format!("sr-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = T;
        let first = sample("instance-1", &"11".repeat(32), t);
        let host = first.host.clone();
        let other = |fetched_at| sample("instance-1", &"00".repeat(32), fetched_at);
        let run = |at| Run { at, tries: 5 };
        let merge =
            |at, bundles: &[Bundle]| Sweep::merge(&dir, &host, run(at), bundles, at).unwrap();

        assert_eq!(merge(t, &[first]).sweep.bundles, ["machine-1.json"]);
        let merged = merge(t + 10 * HOUR, &[other(t + 10 * HOUR)]);
        assert_eq!(merged.sweep.bundles, ["machine-1.json", "machine-2.json"]);

        let merged = merge(t + 20 * HOUR, &[other(t + 20 * HOUR)]);
        assert_eq!(
            (merged.plan.keep, merged.plan.replace),
            (vec![0], vec![(1, 0)])
        );
        assert_eq!(merged.sweep.bundles, ["machine-1.json", "machine-2.json"]);

        let later = t + 25 * HOUR;
        let merged = merge(later, &[]);
        assert_eq!(merged.plan.drop, [0]);
        assert_eq!(merged.sweep.bundles, ["machine-2.json"]);
        assert_eq!(merged.sweep.recent(later), (3, 15));
        assert!(!dir.join("machine-1.json").exists());
        let (_, bundles) = Sweep::read(&dir).unwrap();
        assert_eq!(bundles[0].fetched_at, t + 20 * HOUR);

        assert!(Sweep::merge(&dir, "another.example", run(later), &[], later).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
