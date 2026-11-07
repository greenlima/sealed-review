use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Unknown,
}

/// EAR trustworthiness tiers (draft-ietf-rats-ear).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Affirming,
    Warning,
    Contraindicated,
    None,
}

impl Tier {
    /// Higher is less acceptable: no verdict ranks below a warning, a contraindication lowest.
    fn rank(self) -> u8 {
        match self {
            Tier::Affirming => 0,
            Tier::Warning => 1,
            Tier::None => 2,
            Tier::Contraindicated => 3,
        }
    }

    /// The overall tier of several appraisals; `None` when there are none.
    pub fn worst(tiers: impl IntoIterator<Item = Tier>) -> Tier {
        tiers
            .into_iter()
            .max_by_key(|t| t.rank())
            .unwrap_or(Tier::None)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Link of the verification chain, as numbered on the method page.
    pub link: u8,
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
}

impl Check {
    pub fn new(link: u8, id: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            link,
            id,
            status,
            detail: detail.into(),
        }
    }

    pub fn from_bool(link: u8, id: &'static str, ok: bool, detail: impl Into<String>) -> Self {
        let status = if ok { Status::Pass } else { Status::Fail };
        Self::new(link, id, status, detail)
    }
}

/// Checks without which a verdict on a machine reached directly can never be affirming.
pub const DIRECT: [&str; 14] = [
    "quote_signature",
    "tcb_status",
    "td_attributes",
    "os_image",
    "measurements",
    "rtmr_replay",
    "rtmr3_events",
    "nonce_fresh",
    "signer_bound",
    "tls_bound",
    "config_measured",
    "model_registered",
    "launcher_log_bound",
    "gpu",
];

/// The gateway's own machine: CPU only and without a launcher.
pub const GATEWAY: [&str; 13] = [
    "quote_signature",
    "tcb_status",
    "td_attributes",
    "os_image",
    "measurements",
    "rtmr_replay",
    "rtmr3_events",
    "nonce_fresh",
    "signer_bound",
    "tls_bound",
    "config_measured",
    "no_gpus",
    "compose_pinned",
];

/// A model machine behind the gateway: the client has no connection to it, so it must be one
/// reached directly.
pub const CANDIDATE: [&str; 14] = [
    "quote_signature",
    "tcb_status",
    "td_attributes",
    "os_image",
    "measurements",
    "rtmr_replay",
    "rtmr3_events",
    "nonce_fresh",
    "signer_bound",
    "config_measured",
    "model_requested",
    "reached_directly",
    "launcher_log_bound",
    "gpu",
];

/// Fail-closed: any failure contraindicates; a required check that is missing, duplicated or
/// unknown leaves no verdict; only then do warnings lower an otherwise affirming result.
pub fn tier(checks: &[Check], required: &[&str]) -> Tier {
    if checks.iter().any(|c| c.status == Status::Fail) {
        return Tier::Contraindicated;
    }
    let mut counts: HashMap<&str, usize> = HashMap::with_capacity(checks.len());
    for check in checks.iter().filter(|c| c.status != Status::Unknown) {
        *counts.entry(check.id).or_default() += 1;
    }
    if required.iter().any(|id| counts.get(id) != Some(&1)) {
        return Tier::None;
    }
    if checks.iter().any(|c| c.status != Status::Pass) {
        return Tier::Warning;
    }
    Tier::Affirming
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(status: Status) -> Vec<Check> {
        DIRECT
            .iter()
            .map(|id| Check::new(0, id, status, ""))
            .collect()
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(tier(&[], &DIRECT), Tier::None);
    }

    #[test]
    fn all_pass_is_affirming() {
        assert_eq!(tier(&all(Status::Pass), &DIRECT), Tier::Affirming);
    }

    #[test]
    fn one_fail_contraindicates() {
        let mut checks = all(Status::Pass);
        checks[3].status = Status::Fail;
        assert_eq!(tier(&checks, &DIRECT), Tier::Contraindicated);
    }

    #[test]
    fn unknown_required_is_none() {
        let mut checks = all(Status::Pass);
        checks[4].status = Status::Unknown;
        assert_eq!(tier(&checks, &DIRECT), Tier::None);
    }

    #[test]
    fn missing_required_is_none() {
        let mut checks = all(Status::Pass);
        checks.pop();
        assert_eq!(tier(&checks, &DIRECT), Tier::None);
    }

    #[test]
    fn duplicated_required_is_none() {
        let mut checks = all(Status::Pass);
        checks.push(Check::new(0, DIRECT[0], Status::Pass, ""));
        assert_eq!(tier(&checks, &DIRECT), Tier::None);
    }

    #[test]
    fn required_set_is_per_role() {
        let direct = all(Status::Pass);
        assert_eq!(tier(&direct, &GATEWAY), Tier::None);
        assert_eq!(tier(&direct, &CANDIDATE), Tier::None);
    }

    #[test]
    fn warn_lowers_to_warning() {
        let mut checks = all(Status::Pass);
        checks.push(Check::new(2, "collateral_second_opinion", Status::Warn, ""));
        assert_eq!(tier(&checks, &DIRECT), Tier::Warning);
    }

    #[test]
    fn worst_tier() {
        let (a, w, n, c) = (
            Tier::Affirming,
            Tier::Warning,
            Tier::None,
            Tier::Contraindicated,
        );
        assert_eq!(Tier::worst([]), n);
        assert_eq!(Tier::worst([a, w]), w);
        assert_eq!(Tier::worst([w, n, a]), n);
        assert_eq!(Tier::worst([n, c]), c);
    }

    #[test]
    fn optional_unknown_is_warning() {
        let mut checks = all(Status::Pass);
        checks.push(Check::new(2, "collateral_early", Status::Unknown, ""));
        assert_eq!(tier(&checks, &DIRECT), Tier::Warning);
    }
}
