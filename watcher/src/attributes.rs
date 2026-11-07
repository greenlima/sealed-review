use dcap_qvl::quote::TDReport10;

use crate::verdict::{Check, Status};

const fn bit(n: u32) -> u64 {
    1 << n
}

const fn bits(low: u32, high: u32) -> u64 {
    (u64::MAX >> (63 - high)) & (u64::MAX << low)
}

/// TUD (debug) and TUP (profiling) groups, reserved bits included (ABI spec 348551-008, Table 3.23).
const DEBUG_OR_PROFILING: u64 = bits(0, 15);
/// Reserved SEC bits marked negative, and the bits Intel reserves as must-be-zero.
const RESERVED_NEGATIVE: u64 = bits(23, 26) | bits(32, 61);
const SEPT_VE_DISABLE: u64 = bit(28);
const MIGRATABLE: u64 = bit(29);
const PERFMON: u64 = bit(63);
const ICSSD: u64 = bit(16);

const NAMED: [(u64, &str); 9] = [
    (ICSSD, "ICSSD"),
    (bit(17), "SERVTD_EXT"),
    (bits(18, 22), "RESERVED_P"),
    (bit(27), "LASS"),
    (SEPT_VE_DISABLE, "SEPT_VE_DISABLE"),
    (MIGRATABLE, "MIGRATABLE"),
    (bit(30), "PKS"),
    (bit(31), "KL"),
    (bit(62), "TPA"),
];

const XFAM_PT: u64 = bit(8);
const XFAM_LBR: u64 = bit(15);

/// XFAM observed per dstack OS image (`os_image_hash`), until release records carry it.
const RECORDED_XFAM: [(&str, u64); 2] = [
    (
        "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829",
        0x602e7,
    ),
    (
        "8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd",
        0x602e7,
    ),
];

fn named(attributes: u64) -> Vec<&'static str> {
    NAMED
        .iter()
        .filter(|(mask, _)| attributes & mask != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Every reason the attributes make the TD untrusted for a production Linux guest.
fn violations(attributes: u64) -> Vec<&'static str> {
    [
        (
            attributes & DEBUG_OR_PROFILING != 0,
            "debug or profiling bit set",
        ),
        (
            attributes & RESERVED_NEGATIVE != 0,
            "reserved negative bit set",
        ),
        (attributes & SEPT_VE_DISABLE == 0, "SEPT_VE_DISABLE is 0"),
        (attributes & MIGRATABLE != 0, "MIGRATABLE is 1"),
        (attributes & PERFMON != 0, "PERFMON is 1"),
    ]
    .into_iter()
    .filter_map(|(hit, reason)| hit.then_some(reason))
    .collect()
}

pub fn attributes_check(attributes: u64) -> Check {
    let set = named(attributes);
    let single_step = if attributes & ICSSD == 0 {
        "; ICSSD 0: single-step defense rests on the TDX module version"
    } else {
        ""
    };
    let detail = format!(
        "td_attributes {attributes:#018x} [{}]{single_step}",
        set.join(" ")
    );
    let problems = violations(attributes);
    if problems.is_empty() {
        return Check::new(3, "td_attributes", Status::Pass, detail);
    }
    Check::new(
        3,
        "td_attributes",
        Status::Fail,
        format!("{detail}; {}", problems.join(", ")),
    )
}

pub fn xfam_check(xfam: u64, recorded: Option<u64>) -> Check {
    let tracing = [(XFAM_PT, "Processor Trace"), (XFAM_LBR, "LBR")]
        .into_iter()
        .filter(|(mask, _)| xfam & mask != 0)
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
    let (status, detail) = match recorded {
        None => (
            Status::Unknown,
            format!("xfam {xfam:#x}; none recorded for this OS image"),
        ),
        Some(want) if want != xfam => (Status::Fail, format!("xfam {xfam:#x}, recorded {want:#x}")),
        Some(_) if !tracing.is_empty() => (
            Status::Warn,
            format!("xfam {xfam:#x} enables {}", tracing.join(" and ")),
        ),
        Some(_) => (Status::Pass, format!("xfam {xfam:#x} as recorded")),
    };
    Check::new(3, "xfam", status, detail)
}

pub fn recorded_xfam(os_image_hash: &str) -> Option<u64> {
    RECORDED_XFAM
        .iter()
        .find(|(hash, _)| hash.eq_ignore_ascii_case(os_image_hash))
        .map(|(_, xfam)| *xfam)
}

/// Link 3 beyond the measurements: TD_ATTRIBUTES by Intel's security groups, XFAM against the record.
pub fn checks(td: &TDReport10, os_image_hash: &str) -> [Check; 2] {
    [
        attributes_check(u64::from_le_bytes(td.td_attributes)),
        xfam_check(u64::from_le_bytes(td.xfam), recorded_xfam(os_image_hash)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEAR_ATTRIBUTES: u64 = 0x1000_0000;
    const NEAR_XFAM: u64 = 0x602e7;

    #[test]
    fn near_passes() {
        let check = attributes_check(NEAR_ATTRIBUTES);
        assert_eq!(check.status, Status::Pass);
        assert!(check.detail.contains("SEPT_VE_DISABLE"));
        assert!(check.detail.contains("ICSSD 0"));
    }

    #[test]
    fn debug_fails() {
        assert_eq!(attributes_check(NEAR_ATTRIBUTES | 1).status, Status::Fail);
    }

    #[test]
    fn profiling_fails() {
        assert_eq!(
            attributes_check(NEAR_ATTRIBUTES | bit(5)).status,
            Status::Fail
        );
    }

    #[test]
    fn reserved_negative_fails() {
        assert_eq!(
            attributes_check(NEAR_ATTRIBUTES | bit(25)).status,
            Status::Fail
        );
        assert_eq!(
            attributes_check(NEAR_ATTRIBUTES | bit(40)).status,
            Status::Fail
        );
    }

    #[test]
    fn sept_ve_enabled_fails() {
        let check = attributes_check(0);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("SEPT_VE_DISABLE is 0"));
    }

    #[test]
    fn migratable_and_perfmon_fail() {
        assert_eq!(
            attributes_check(NEAR_ATTRIBUTES | MIGRATABLE).status,
            Status::Fail
        );
        assert_eq!(
            attributes_check(NEAR_ATTRIBUTES | PERFMON).status,
            Status::Fail
        );
    }

    #[test]
    fn positive_bits_pass_and_are_named() {
        let check = attributes_check(NEAR_ATTRIBUTES | ICSSD | bit(27) | bit(30));
        assert_eq!(check.status, Status::Pass);
        assert!(check.detail.contains("ICSSD LASS SEPT_VE_DISABLE PKS"));
        assert!(!check.detail.contains("ICSSD 0"));
    }

    #[test]
    fn group_masks() {
        assert_eq!(DEBUG_OR_PROFILING, 0xffff);
        assert_eq!(bits(23, 26), 0x0780_0000);
        assert_eq!(bits(32, 61), 0x3fff_ffff_0000_0000);
    }

    #[test]
    fn xfam_as_recorded_passes() {
        let recorded =
            recorded_xfam("91FD5D69CCEE3E5EA4F2AEB8C9B632C4358C4ECFC29BA1AA6FB1E402AF209829");
        assert_eq!(xfam_check(NEAR_XFAM, recorded).status, Status::Pass);
    }

    #[test]
    fn xfam_changed_fails() {
        assert_eq!(
            xfam_check(NEAR_XFAM | XFAM_PT, Some(NEAR_XFAM)).status,
            Status::Fail
        );
    }

    #[test]
    fn xfam_tracing_warns() {
        let traced = NEAR_XFAM | XFAM_LBR;
        assert_eq!(xfam_check(traced, Some(traced)).status, Status::Warn);
    }

    #[test]
    fn xfam_unrecorded_is_unknown() {
        assert_eq!(recorded_xfam("00"), None);
        assert_eq!(xfam_check(NEAR_XFAM, None).status, Status::Unknown);
    }
}
