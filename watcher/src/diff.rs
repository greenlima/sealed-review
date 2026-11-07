use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;

use crate::bundle::Bundle;
use crate::report::Report;
use crate::review::Review;
use crate::verdict::{Check, Status, Tier};

/// What changed on one endpoint between two observations.
#[derive(Debug, Serialize)]
pub struct Diff {
    pub host: String,
    pub from: u64,
    pub to: u64,
    /// Replicas of one endpoint differ in instance, compose and launcher log without any change.
    pub same_instance: bool,
    /// `[before, after]` when the tier moved.
    pub tier: Option<[Tier; 2]>,
    pub facts: Vec<FactChange>,
    pub checks: Vec<CheckChange>,
    pub launcher: Launcher,
}

#[derive(Debug, Serialize)]
pub struct FactChange {
    pub fact: String,
    pub from: Value,
    pub to: Value,
}

/// A check whose status moved, appeared or disappeared; `detail` is the later one.
#[derive(Debug, Serialize)]
pub struct CheckChange {
    pub id: &'static str,
    pub from: Option<Status>,
    pub to: Option<Status>,
    pub detail: Option<String>,
}

/// The launcher's action log only grows within one CVM; anything else is a new or rewritten log.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "log", rename_all = "snake_case")]
pub enum Launcher {
    Absent,
    Unchanged,
    Appended { actions: Vec<Value> },
    Replaced { from: usize, to: usize },
}

fn facts(old: &Review, new: &Review) -> Result<Vec<FactChange>> {
    let (Value::Object(before), Value::Object(after)) = (
        serde_json::to_value(&old.facts)?,
        serde_json::to_value(&new.facts)?,
    ) else {
        return Ok(Vec::new());
    };
    Ok(before
        .into_iter()
        .filter_map(|(fact, from)| {
            let to = after.get(&fact).cloned().unwrap_or(Value::Null);
            (from != to).then_some(FactChange { fact, from, to })
        })
        .collect())
}

fn checks(old: &[Check], new: &[Check]) -> Vec<CheckChange> {
    let before: BTreeMap<&str, &Check> = old.iter().map(|c| (c.id, c)).collect();
    let after: BTreeMap<&str, &Check> = new.iter().map(|c| (c.id, c)).collect();
    let ids: BTreeSet<&'static str> = old.iter().chain(new).map(|c| c.id).collect();
    ids.into_iter()
        .filter_map(|id| {
            let (from, to) = (before.get(id), after.get(id));
            let moved = from.map(|c| c.status) != to.map(|c| c.status);
            moved.then(|| CheckChange {
                id,
                from: from.map(|c| c.status),
                to: to.map(|c| c.status),
                detail: to.map(|c| c.detail.clone()),
            })
        })
        .collect()
}

fn actions(bundle: &Bundle) -> Result<Option<Vec<Value>>> {
    Ok(Report::parse(&bundle.report)?
        .compose_manager_attestation
        .map(|c| c.actions))
}

pub fn launcher(old: Option<&[Value]>, new: Option<&[Value]>) -> Launcher {
    match (old, new) {
        (None, None) => Launcher::Absent,
        (Some(a), Some(b)) if a == b => Launcher::Unchanged,
        (Some(a), Some(b)) if b.starts_with(a) => Launcher::Appended {
            actions: b[a.len()..].to_vec(),
        },
        (a, b) => Launcher::Replaced {
            from: a.map_or(0, <[Value]>::len),
            to: b.map_or(0, <[Value]>::len),
        },
    }
}

/// Compares two reviews of the same endpoint and the launcher logs of their bundles.
pub fn diff(old: (&Bundle, &Review), new: (&Bundle, &Review)) -> Result<Diff> {
    let ((old_bundle, old), (new_bundle, new)) = (old, new);
    ensure!(
        old.host == new.host,
        "bundles are from {} and {}",
        old.host,
        new.host
    );
    let (before, after) = (actions(old_bundle)?, actions(new_bundle)?);
    Ok(Diff {
        host: new.host.clone(),
        from: old.fetched_at,
        to: new.fetched_at,
        same_instance: old.facts.instance_id == new.facts.instance_id,
        tier: (old.tier != new.tier).then_some([old.tier, new.tier]),
        facts: facts(old, new)?,
        checks: checks(&old.checks, &new.checks),
        launcher: launcher(before.as_deref(), after.as_deref()),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn launcher_log_cases() {
        let a = [json!({"action": "compose_up"})];
        let b = [a[0].clone(), json!({"action": "compose_down"})];
        assert_eq!(launcher(None, None), Launcher::Absent);
        assert_eq!(launcher(Some(&a), Some(&a)), Launcher::Unchanged);
        assert_eq!(
            launcher(Some(&a), Some(&b)),
            Launcher::Appended {
                actions: vec![b[1].clone()]
            }
        );
        assert_eq!(
            launcher(Some(&b), Some(&a)),
            Launcher::Replaced { from: 2, to: 1 }
        );
        assert_eq!(
            launcher(Some(&a), None),
            Launcher::Replaced { from: 1, to: 0 }
        );
    }

    #[test]
    fn only_moved_checks_are_listed() {
        let old = [
            Check::new(1, "a", Status::Pass, "x"),
            Check::new(1, "b", Status::Pass, "x"),
            Check::new(1, "c", Status::Warn, "x"),
        ];
        let new = [
            Check::new(1, "a", Status::Pass, "y"),
            Check::new(1, "b", Status::Fail, "z"),
            Check::new(1, "d", Status::Pass, "w"),
        ];
        let moved: Vec<(&str, Option<Status>, Option<Status>)> = checks(&old, &new)
            .into_iter()
            .map(|c| (c.id, c.from, c.to))
            .collect();
        assert_eq!(
            moved,
            vec![
                ("b", Some(Status::Pass), Some(Status::Fail)),
                ("c", Some(Status::Warn), None),
                ("d", None, Some(Status::Pass)),
            ]
        );
    }
}
