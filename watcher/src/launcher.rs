use std::collections::BTreeSet;

use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::TDReport10;
use sha2::{Digest, Sha256};

use crate::quote::appraise;
use crate::report::ComposeManager;
use crate::verdict::{Check, Status};

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

    #[test]
    fn non_ascii_is_escaped_like_python() {
        let mut out = String::new();
        encode(&serde_json::json!({"b": "é😀", "a": 1}), &mut out);
        assert_eq!(out, r#"{"a":1,"b":"\u00e9\ud83d\ude00"}"#);
    }
}
