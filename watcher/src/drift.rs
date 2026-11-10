use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::Serialize;

use crate::feed::{Current, Reviewed};
use crate::fetch::{self, Coverage};
use crate::gate::connect;
use crate::gateway;
use crate::launcher::{self, Workload};

/// The gateway machine of a route: a fresh gateway answer carries only the candidates.
const GATEWAY_SCOPE: &str = "gateway/";

/// One machine as a fresh fetch found it, against its host's current verdict.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Seen {
    /// Runs the workload the verdict recorded.
    Unchanged { scope: String },
    /// Runs another workload, so the verdict no longer describes what serves requests.
    Changed { scope: String, changes: Vec<String> },
    /// The verdict predates workload records: nothing to compare.
    Unrecorded { scope: String },
    /// Reached, but not reviewed: the gate refuses its TLS key.
    NotReviewed { instance_id: String },
    /// Reviewed, but not reached by this fetch.
    NotReached { scope: String },
}

/// What a fresh fetch found for one host's current verdict.
#[derive(Debug, Serialize)]
pub struct Drift {
    pub host: String,
    pub seq: u64,
    pub machines: Vec<Seen>,
}

impl Drift {
    pub fn changed(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.machines.iter().filter_map(|m| match m {
            Seen::Changed { scope, changes } => Some((scope.as_str(), changes.as_slice())),
            _ => None,
        })
    }
}

/// A machine reached now: its instance id and the workload its launcher log leaves running.
pub type Observed = (String, Option<Workload>);

/// The machines serving `current`'s host now: the candidates of one gateway answer for a route,
/// a sweep of reports for a host reached directly.
pub async fn observe(current: &Current, coverage: Coverage) -> Result<Vec<Observed>> {
    let reports = match connect(&current.host) {
        (_, Some(model)) => gateway::candidates(model).await?,
        (host, None) => fetch::reports(host, coverage).await?,
    };
    Ok(reports
        .into_iter()
        .map(|r| {
            let workload = r
                .compose_manager_attestation
                .map(|m| launcher::workload(&m.actions));
            (r.info.instance_id, workload)
        })
        .collect())
}

fn seen(reviewed: &Reviewed, now: Option<&Workload>) -> Seen {
    let scope = reviewed.scope.clone();
    let Some(before) = &reviewed.workload else {
        return Seen::Unrecorded { scope };
    };
    let Some(now) = now else {
        return Seen::Changed {
            scope,
            changes: vec!["the report carries no launcher log".into()],
        };
    };
    let changes = launcher::changes(before, now);
    if changes.is_empty() {
        return Seen::Unchanged { scope };
    }
    Seen::Changed { scope, changes }
}

/// Matches the machines reached with the ones the verdict reviewed, by instance id.
pub fn compare(current: &Current, observed: &[Observed]) -> Drift {
    let reviewed: HashMap<&str, &Reviewed> = current
        .machines
        .iter()
        .filter_map(|m| m.instance_id.as_deref().map(|id| (id, m)))
        .collect();
    let reached: HashSet<&str> = observed.iter().map(|(id, _)| id.as_str()).collect();
    let found = observed
        .iter()
        .map(|(id, now)| match reviewed.get(id.as_str()) {
            Some(m) => seen(m, now.as_ref()),
            None => Seen::NotReviewed {
                instance_id: id.clone(),
            },
        });
    let missed = current
        .machines
        .iter()
        .filter(|m| !m.scope.starts_with(GATEWAY_SCOPE))
        .filter(|m| {
            m.instance_id
                .as_deref()
                .is_none_or(|id| !reached.contains(id))
        })
        .map(|m| Seen::NotReached {
            scope: m.scope.clone(),
        });
    Drift {
        host: current.host.clone(),
        seq: current.seq,
        machines: found.chain(missed).collect(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::verdict::Tier;

    fn workload(sha: &str) -> Workload {
        launcher::workload(&[json!({
            "action": "compose_up", "file": "glm.yaml", "file_sha256": sha, "services": "['r1']"
        })])
    }

    fn reviewed(scope: &str, id: &str, workload: Option<Workload>) -> Reviewed {
        Reviewed {
            scope: scope.into(),
            instance_id: Some(id.into()),
            workload,
        }
    }

    fn current(machines: Vec<Reviewed>) -> Current {
        Current {
            host: "model.example".into(),
            seq: 3,
            status: Tier::Warning,
            exp: 0,
            expired: false,
            corrected_by: None,
            tls_keys: Vec::new(),
            model_keys: Vec::new(),
            open: Vec::new(),
            machines,
        }
    }

    #[test]
    fn each_machine_is_matched_by_instance() {
        let verdict = current(vec![
            reviewed("a", "i1", Some(workload("s1"))),
            reviewed("b", "i2", Some(workload("s1"))),
            reviewed("c", "i3", Some(workload("s1"))),
            reviewed("old", "i4", None),
            reviewed("gateway/g1/aa", "g1", None),
            reviewed("older", "i5", None),
        ]);
        let observed = [
            ("i1".to_owned(), Some(workload("s1"))),
            ("i2".to_owned(), Some(workload("s2"))),
            ("i4".to_owned(), Some(workload("s2"))),
            ("i9".to_owned(), Some(workload("s1"))),
        ];
        let drift = compare(&verdict, &observed);
        assert_eq!(
            drift.machines,
            vec![
                Seen::Unchanged { scope: "a".into() },
                Seen::Changed {
                    scope: "b".into(),
                    changes: vec!["[r1]: reviewed glm.yaml s1, now glm.yaml s2".into()],
                },
                Seen::Unrecorded {
                    scope: "old".into()
                },
                Seen::NotReviewed {
                    instance_id: "i9".into()
                },
                Seen::NotReached { scope: "c".into() },
                Seen::NotReached {
                    scope: "older".into()
                },
            ]
        );
        assert_eq!(
            drift.changed().map(|(scope, _)| scope).collect::<Vec<_>>(),
            ["b"]
        );
    }

    #[test]
    fn a_lost_launcher_log_is_a_change() {
        let verdict = current(vec![reviewed("a", "i1", Some(workload("s1")))]);
        let drift = compare(&verdict, &[("i1".to_owned(), None)]);
        assert_eq!(drift.changed().count(), 1);
    }
}
