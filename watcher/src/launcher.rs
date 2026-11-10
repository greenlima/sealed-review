use std::collections::{BTreeMap, BTreeSet};

use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::TDReport10;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::quote::appraise;
use crate::report::ComposeManager;
use crate::verdict::{Check, Status};

/// The release a `compose_up` names: its file's SHA-256 and the tag and commit it came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Release {
    pub sha256: Option<String>,
    pub tag: Option<String>,
    pub commit: Option<String>,
}

/// Services started from one deployment file at one release, and not stopped since.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub file: String,
    #[serde(flatten)]
    pub release: Release,
    /// `*` when the launcher started every service of the file.
    pub services: Vec<String>,
}

/// What the launcher's log leaves running: the compose-manager image last started and the deployments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    pub manager: Option<String>,
    pub deployments: Vec<Deployment>,
}

const EVERY_SERVICE: &str = "*";

fn text<'a>(action: &'a Value, key: &str) -> Option<&'a str> {
    action.get(key).and_then(Value::as_str)
}

/// The services an action names: a JSON list, or the Python list repr the launcher writes.
fn services(action: &Value) -> Vec<String> {
    match action.get("services") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(repr)) => repr
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"'))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Where a service runs: services share one compose project, so the last `compose_up` naming a
/// service replaces it, whatever its file. `*` (every service of a file) is kept per file.
fn slot(file: &str, service: &str) -> String {
    if service == EVERY_SERVICE {
        return format!("{EVERY_SERVICE} {file}");
    }
    service.to_owned()
}

/// Replays the log once: each `compose_up` starts its services at its release, each `compose_down`
/// stops the ones it names (all of its file's when it names none). A service the log never stops
/// stays listed, as the log alone cannot show an orphan removed.
pub fn workload(actions: &[Value]) -> Workload {
    let mut manager = None;
    let mut running: BTreeMap<String, (String, String, Release)> = BTreeMap::new();
    for action in actions {
        let (kind, file) = (text(action, "action"), text(action, "file"));
        match (kind, file) {
            (Some("compose_manager_started"), _) => {
                manager = text(action, "image").map(str::to_owned);
            }
            (Some("compose_up"), Some(file)) => {
                let release = Release {
                    sha256: text(action, "file_sha256").map(str::to_owned),
                    tag: text(action, "tag").map(str::to_owned),
                    commit: text(action, "commit").map(str::to_owned),
                };
                let mut named = services(action);
                if named.is_empty() {
                    named.push(EVERY_SERVICE.to_owned());
                }
                for service in named {
                    let entry = (file.to_owned(), service.clone(), release.clone());
                    running.insert(slot(file, &service), entry);
                }
            }
            (Some("compose_down"), Some(file)) => {
                let named = services(action);
                if named.is_empty() {
                    running.retain(|_, (f, _, _)| f != file);
                    continue;
                }
                for service in named {
                    running.remove(&slot(file, &service));
                }
            }
            _ => {}
        }
    }
    let mut grouped: BTreeMap<(String, Release), Vec<String>> = BTreeMap::new();
    for (file, service, release) in running.into_values() {
        grouped.entry((file, release)).or_default().push(service);
    }
    Workload {
        manager,
        deployments: grouped
            .into_iter()
            .map(|((file, release), mut services)| {
                services.sort();
                Deployment {
                    file,
                    release,
                    services,
                }
            })
            .collect(),
    }
}

fn short(digest: &str) -> &str {
    let hex = digest.rsplit(':').next().unwrap_or(digest);
    &hex[..hex.len().min(12)]
}

fn release_name(running: Option<&(&str, &Release)>) -> String {
    let Some((file, release)) = running else {
        return "not running".into();
    };
    let sha = release.sha256.as_deref().map_or("no SHA-256", short);
    match &release.tag {
        Some(tag) => format!("{file} {sha} ({tag})"),
        None => format!("{file} {sha}"),
    }
}

/// Each running slot with the file and release it runs from.
fn index(w: &Workload) -> BTreeMap<String, (&str, &Release)> {
    w.deployments
        .iter()
        .flat_map(|d| {
            d.services
                .iter()
                .map(move |s| (slot(&d.file, s), (d.file.as_str(), &d.release)))
        })
        .collect()
}

/// What a slot's code is: its file and that file's SHA-256, not the tag it was deployed under.
fn content<'a>(running: Option<&(&'a str, &'a Release)>) -> Option<(&'a str, Option<&'a str>)> {
    running.map(|(file, release)| (*file, release.sha256.as_deref()))
}

/// Each way `now` differs from `reviewed`, one line per transition with the services that made it.
/// A new tag or commit on the same file content is no change.
pub fn changes(reviewed: &Workload, now: &Workload) -> Vec<String> {
    let (before, after) = (index(reviewed), index(now));
    let slots: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut moved: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for slot in slots {
        let (from, to) = (before.get(slot), after.get(slot));
        if content(from) == content(to) {
            continue;
        }
        let service = slot.split(' ').next().unwrap_or(slot).to_owned();
        moved
            .entry((release_name(from), release_name(to)))
            .or_default()
            .push(service);
    }
    let manager = (reviewed.manager != now.manager).then(|| {
        let name = |m: &Option<String>| {
            m.as_deref()
                .map_or("none".to_owned(), |m| short(m).to_owned())
        };
        format!(
            "compose-manager: reviewed {}, now {}",
            name(&reviewed.manager),
            name(&now.manager)
        )
    });
    manager
        .into_iter()
        .chain(moved.into_iter().map(|((from, to), services)| {
            format!("[{}]: reviewed {from}, now {to}", services.join(", "))
        }))
        .collect()
}

/// `actions_hash` as the compose manager computes it: SHA-256 of the compact, key-sorted,
/// ASCII-escaped JSON list (Python's `json.dumps(sort_keys=True, separators=(",", ":"))`).
pub fn actions_hash(actions: &[serde_json::Value]) -> String {
    let mut encoded = String::new();
    encode(&serde_json::Value::Array(actions.to_vec()), &mut encoded);
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

fn encode(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_str(key, out);
                out.push(':');
                encode(&map[key], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out);
            }
            out.push(']');
        }
        serde_json::Value::String(s) => encode_str(s, out),
        scalar => out.push_str(&scalar.to_string()),
    }
}

fn encode_str(s: &str, out: &mut String) {
    let quoted = serde_json::to_string(s).unwrap_or_default();
    let mut units = [0u16; 2];
    for ch in quoted.chars() {
        if ch.is_ascii() {
            out.push(ch);
            continue;
        }
        for unit in ch.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
}

fn same_cvm(a: &TDReport10, b: &TDReport10) -> bool {
    a.mr_td == b.mr_td
        && a.mr_config_id == b.mr_config_id
        && a.rt_mr0 == b.rt_mr0
        && a.rt_mr1 == b.rt_mr1
        && a.rt_mr2 == b.rt_mr2
        && a.rt_mr3 == b.rt_mr3
}

fn summary(actions: &[serde_json::Value]) -> String {
    let field = |a: &serde_json::Value, k: &str| {
        a.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let images: BTreeSet<String> = actions.iter().filter_map(|a| field(a, "image")).collect();
    let ups = actions
        .iter()
        .filter(|a| field(a, "action").as_deref() == Some("compose_up"))
        .count();
    format!(
        "{} actions, {ups} compose_up, images [{}]",
        actions.len(),
        images.into_iter().collect::<Vec<_>>().join(", ")
    )
}

/// Link 7: the launcher's action log is authentic (its hash recomputes), fresh (our nonce), and
/// quoted by the same CVM as the main report.
pub fn check(
    manager: Option<&ComposeManager>,
    td: &TDReport10,
    collateral: Option<&QuoteCollateralV3>,
    nonce: &str,
    now: u64,
) -> Check {
    let Some(manager) = manager else {
        return Check::new(
            7,
            "launcher_log_bound",
            Status::Fail,
            "no compose-manager attestation in the report",
        );
    };
    let Some(collateral) = collateral else {
        return Check::new(
            7,
            "launcher_log_bound",
            Status::Unknown,
            "no Intel collateral to verify its quote",
        );
    };
    let quote = hex::decode(&manager.quote).unwrap_or_default();
    let appraisal = match appraise(&quote, collateral, now) {
        Ok(a) => a,
        Err(e) => {
            return Check::new(
                7,
                "launcher_log_bound",
                Status::Fail,
                format!("its quote: {e:#}"),
            );
        }
    };
    let recomputed = actions_hash(&manager.actions);
    let expected_data = format!("{recomputed}{nonce}");
    let failures: Vec<&str> = [
        (
            recomputed.eq_ignore_ascii_case(&manager.actions_hash),
            "actions_hash does not recompute",
        ),
        (
            manager.nonce.eq_ignore_ascii_case(nonce) && manager.nonce_source == "client",
            "not our nonce",
        ),
        (
            hex::encode(appraisal.td.report_data).eq_ignore_ascii_case(&expected_data),
            "report_data is not actions_hash || nonce",
        ),
        (same_cvm(&appraisal.td, td), "quoted by a different CVM"),
    ]
    .into_iter()
    .filter_map(|(ok, why)| (!ok).then_some(why))
    .collect();
    if failures.is_empty() {
        return Check::new(
            7,
            "launcher_log_bound",
            Status::Pass,
            summary(&manager.actions),
        );
    }
    Check::new(7, "launcher_log_bound", Status::Fail, failures.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_hash_sorts_keys_and_is_compact() {
        let actions = vec![serde_json::json!({"timestamp": "t", "action": "compose_up"})];
        let expected = hex::encode(Sha256::digest(
            br#"[{"action":"compose_up","timestamp":"t"}]"#,
        ));
        assert_eq!(actions_hash(&actions), expected);
    }

    fn up(file: &str, sha: &str, tag: &str, services: &str) -> Value {
        serde_json::json!({"action": "compose_up", "file": file, "file_sha256": sha, "tag": tag, "commit": "c", "services": services})
    }

    fn down(file: &str, services: &str) -> Value {
        serde_json::json!({"action": "compose_down", "file": file, "services": services})
    }

    #[test]
    fn the_log_replays_to_what_runs() {
        let actions = [
            serde_json::json!({"action": "compose_manager_started", "image": "m@sha256:aa"}),
            up("glm.yaml", "s1", "v1", "['proxy', 'model-r1', 'model-r2']"),
            up("rotate.yaml", "t", "v2", "['rotate-token']"),
            down("rotate.yaml", "['rotate-token']"),
            up("glm.yaml", "s2", "v3", "['proxy']"),
            serde_json::json!({"action": "docker_restart", "container": "nginx"}),
            serde_json::json!({"action": "compose_manager_started", "image": "m@sha256:bb"}),
        ];
        let w = workload(&actions);
        assert_eq!(w.manager.as_deref(), Some("m@sha256:bb"));
        let seen: Vec<(&str, Option<&str>, Vec<&str>)> = w
            .deployments
            .iter()
            .map(|d| {
                (
                    d.file.as_str(),
                    d.release.sha256.as_deref(),
                    d.services.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("glm.yaml", Some("s1"), vec!["model-r1", "model-r2"]),
                ("glm.yaml", Some("s2"), vec!["proxy"]),
            ]
        );
    }

    #[test]
    fn a_down_without_services_stops_the_whole_file() {
        let actions = [
            up("a.yaml", "s", "v1", "['x', 'y']"),
            serde_json::json!({"action": "compose_down", "file": "a.yaml"}),
            serde_json::json!({"action": "compose_up", "file": "b.yaml", "file_sha256": "s", "services": ["z"]}),
        ];
        let w = workload(&actions);
        assert_eq!(w.deployments.len(), 1);
        assert_eq!(w.deployments[0].file, "b.yaml");
        assert_eq!(w.deployments[0].services, vec!["z"]);
    }

    #[test]
    fn a_service_belongs_to_the_last_file_that_started_it() {
        let actions = [
            up("canary.yaml", "c", "v1", "['r3', 'r4']"),
            up("glm.yaml", "g", "v2", "['r3']"),
        ];
        let replayed = workload(&actions);
        let files: Vec<(&str, Vec<&str>)> = replayed
            .deployments
            .iter()
            .map(|d| {
                (
                    d.file.as_str(),
                    d.services.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            files,
            vec![("canary.yaml", vec!["r4"]), ("glm.yaml", vec!["r3"])]
        );
    }

    #[test]
    fn changes_name_each_moved_service_but_not_a_new_tag() {
        let reviewed = workload(&[up("glm.yaml", "aaaa", "v1", "['proxy', 'r1', 'r2']")]);
        let retagged = workload(&[up("glm.yaml", "aaaa", "v2", "['proxy', 'r1', 'r2']")]);
        assert!(changes(&reviewed, &retagged).is_empty());
        let moved = workload(&[
            up("glm.yaml", "aaaa", "v1", "['proxy', 'r1', 'r2']"),
            up("glm.yaml", "bbbb", "v3", "['r1', 'r2']"),
            serde_json::json!({"action": "compose_manager_started", "image": "m@sha256:cc"}),
        ]);
        assert_eq!(
            changes(&reviewed, &moved),
            vec![
                "compose-manager: reviewed none, now cc".to_owned(),
                "[r1, r2]: reviewed glm.yaml aaaa (v1), now glm.yaml bbbb (v3)".to_owned(),
            ]
        );
    }

    #[test]
    fn non_ascii_is_escaped_like_python() {
        let mut out = String::new();
        encode(&serde_json::json!({"b": "é😀", "a": 1}), &mut out);
        assert_eq!(out, r#"{"a":1,"b":"\u00e9\ud83d\ude00"}"#);
    }
}
