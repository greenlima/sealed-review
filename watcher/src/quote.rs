use anyhow::{Context, Result};
use dcap_qvl::quote::TDReport10;
use dcap_qvl::verify::verify;
use dcap_qvl::{QuoteCollateralV3, TcbInfo};

use crate::bundle::{Bundle, Source, Stream};
use crate::verdict::{Check, Status};

/// A quote verified against one collateral set at the bundle's fetch time.
#[derive(Debug, Clone)]
pub struct Appraisal {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub evaluation_number: u32,
    pub next_update: String,
    pub td: TDReport10,
}

/// Why no appraisal exists: the collateral never arrived, or the quote did not verify with it.
#[derive(Debug)]
pub enum Failure {
    Missing(String),
    Invalid(String),
}

impl Failure {
    fn status(&self) -> Status {
        match self {
            Failure::Missing(_) => Status::Unknown,
            Failure::Invalid(_) => Status::Fail,
        }
    }

    fn detail(&self) -> &str {
        match self {
            Failure::Missing(e) | Failure::Invalid(e) => e,
        }
    }
}

pub fn appraise(quote: &[u8], collateral: &QuoteCollateralV3, now: u64) -> Result<Appraisal> {
    let verified = verify(quote, collateral, now)?;
    let td = *verified.report.as_td10().context("not a TDX quote")?;
    let info: TcbInfo =
        serde_json::from_str(&collateral.tcb_info).context("TCB info is not JSON")?;
    Ok(Appraisal {
        status: verified.status,
        advisory_ids: verified.advisory_ids,
        evaluation_number: info.tcb_evaluation_data_number,
        next_update: info.next_update,
        td,
    })
}

pub fn appraise_from(
    bundle: &Bundle,
    quote: &[u8],
    source: Source,
    stream: Stream,
) -> Result<Appraisal, Failure> {
    let collateral = bundle
        .collateral(source, stream)
        .ok_or_else(|| Failure::Missing("not fetched".to_owned()))?;
    let data = collateral
        .data
        .as_ref()
        .ok_or_else(|| Failure::Missing(collateral.error.clone().unwrap_or_default()))?;
    appraise(quote, data, bundle.fetched_at).map_err(|e| Failure::Invalid(format!("{e:#}")))
}

fn describe(a: &Appraisal) -> String {
    format!(
        "{} (TCB evaluation data number {}, next update {}, advisories [{}])",
        a.status,
        a.evaluation_number,
        a.next_update,
        a.advisory_ids.join(", ")
    )
}

fn tcb_status(a: &Appraisal) -> Status {
    match a.status.as_str() {
        "UpToDate" => Status::Pass,
        "SWHardeningNeeded" => Status::Warn,
        _ => Status::Fail,
    }
}

fn compare(id: &'static str, reference: &Appraisal, other: Result<Appraisal, Failure>) -> Check {
    match other {
        Err(Failure::Missing(e)) => Check::new(2, id, Status::Unknown, e),
        Err(Failure::Invalid(e)) => {
            Check::new(2, id, Status::Warn, format!("does not verify: {e}"))
        }
        Ok(o)
            if o.status == reference.status
                && o.evaluation_number == reference.evaluation_number =>
        {
            Check::new(2, id, Status::Pass, describe(&o))
        }
        Ok(o) => Check::new(
            2,
            id,
            Status::Warn,
            format!("differs from Intel's standard set: {}", describe(&o)),
        ),
    }
}

/// Links 1–2: the quote's signature chain and its TCB status, from Intel's standard collateral,
/// compared with Intel's early stream and with Phala's cache.
pub fn checks(bundle: &Bundle, quote: &[u8]) -> (Vec<Check>, Option<Appraisal>) {
    let reference = match appraise_from(bundle, quote, Source::Intel, Stream::Standard) {
        Ok(a) => a,
        Err(failure) => {
            let checks = vec![
                Check::new(
                    1,
                    "quote_signature",
                    failure.status(),
                    format!("Intel collateral: {}", failure.detail()),
                ),
                Check::new(2, "tcb_status", Status::Unknown, "quote not verified"),
            ];
            return (checks, None);
        }
    };
    let early = appraise_from(bundle, quote, Source::Intel, Stream::Early);
    let phala = appraise_from(bundle, quote, Source::Phala, Stream::Standard);

    let checks = vec![
        Check::new(
            1,
            "quote_signature",
            Status::Pass,
            "PCK chain, QE report and quote signature verify against Intel's root",
        ),
        Check::new(
            2,
            "tcb_status",
            tcb_status(&reference),
            describe(&reference),
        ),
        compare("collateral_early", &reference, early),
        compare("collateral_second_opinion", &reference, phala),
    ];
    (checks, Some(reference))
}
