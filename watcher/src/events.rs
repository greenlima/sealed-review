use dcap_qvl::quote::TDReport10;
use sha2::{Digest, Sha256, Sha384};

use crate::report::Event;
use crate::verdict::Check;

/// dstack's runtime event digest: `SHA-384(event_type LE32 || ":" || event || ":" || payload)`.
pub fn runtime_digest(event: &Event, payload: &[u8]) -> [u8; 48] {
    Sha384::new()
        .chain_update(event.event_type.to_le_bytes())
        .chain_update(b":")
        .chain_update(event.event.as_bytes())
        .chain_update(b":")
        .chain_update(payload)
        .finalize()
        .into()
}

fn extend(register: &mut [u8; 48], digest: &[u8]) {
    *register = Sha384::new()
        .chain_update(*register)
        .chain_update(digest)
        .finalize()
        .into();
}

/// Replays all four RTMRs in one pass, recomputing and cross-checking every RTMR3 event.
pub fn checks(
    events: &[Event],
    td: &TDReport10,
    app_compose: &str,
    os_image_hash: &[u8],
) -> Vec<Check> {
    let mut registers = [[0u8; 48]; 4];
    let mut bad_digests: Vec<&str> = Vec::new();
    let mut compose_event: Option<Vec<u8>> = None;
    let mut image_event: Option<Vec<u8>> = None;
    let mut malformed = false;

    for event in events {
        let (Ok(digest), Some(register)) = (
            hex::decode(&event.digest),
            registers.get_mut(event.imr as usize),
        ) else {
            malformed = true;
            continue;
        };
        if event.imr != 3 {
            extend(register, &digest);
            continue;
        }
        let payload = hex::decode(&event.event_payload).unwrap_or_default();
        let computed = runtime_digest(event, &payload);
        if !digest.is_empty() && digest != computed {
            bad_digests.push(&event.event);
        }
        extend(register, &computed);
        match event.event.as_str() {
            "compose-hash" => compose_event = Some(payload),
            "os-image-hash" => image_event = Some(payload),
            _ => {}
        }
    }

    let quoted = [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3];
    let mismatched: Vec<String> = (0..4)
        .filter(|&i| registers[i] != quoted[i])
        .map(|i| format!("RTMR{i}"))
        .collect();
    let replay_ok = !malformed && mismatched.is_empty();
    let replay_detail = if replay_ok {
        format!("{} events replay to RTMR0–3", events.len())
    } else {
        format!(
            "mismatch: [{}]; malformed events: {malformed}",
            mismatched.join(", ")
        )
    };

    let compose_hash = Sha256::digest(app_compose.as_bytes());
    let compose_ok = compose_event.as_deref() == Some(compose_hash.as_slice());
    let image_ok = image_event.as_deref() == Some(os_image_hash);
    let events_ok = bad_digests.is_empty() && compose_ok && image_ok;
    let events_detail = format!(
        "digests recomputed (bad: [{}]); compose-hash event matches app_compose: {compose_ok}; \
         os-image-hash event matches vm_config: {image_ok}",
        bad_digests.join(", ")
    );

    vec![
        Check::from_bool(3, "rtmr_replay", replay_ok, replay_detail),
        Check::from_bool(5, "rtmr3_events", events_ok, events_detail),
    ]
}
