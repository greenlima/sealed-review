use serde::{Deserialize, Serialize};

use crate::report::Event;

/// The key service a machine measured into RTMR3 at boot (dstack's `key-provider` event).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    /// For dstack's KMS, the hex DER SubjectPublicKeyInfo of its root key.
    pub id: String,
}

/// Trusted only as far as `rtmr_replay` and `rtmr3_events` pass; none unless exactly one such event.
pub fn measured(events: &[Event]) -> Option<Provider> {
    let mut found = events
        .iter()
        .filter(|e| e.imr == 3 && e.event == "key-provider");
    let event = found.next()?;
    if found.next().is_some() {
        return None;
    }
    serde_json::from_slice(&hex::decode(&event.event_payload).ok()?).ok()
}

/// The compose's `key_provider_id`; empty means any key service is accepted.
pub fn pinned(app_compose: &str) -> Option<String> {
    let compose: serde_json::Value = serde_json::from_str(app_compose).ok()?;
    compose.get("key_provider_id")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(imr: u32, name: &str, payload: &str) -> Event {
        Event {
            imr,
            event_type: 0x0800_0001,
            digest: String::new(),
            event: name.to_owned(),
            event_payload: hex::encode(payload),
        }
    }

    #[test]
    fn reads_the_rtmr3_event_only() {
        let events = [
            event(2, "key-provider", r#"{"name":"forged","id":"00"}"#),
            event(3, "key-provider", r#"{"name":"kms","id":"3059"}"#),
        ];
        assert_eq!(
            measured(&events),
            Some(Provider {
                name: "kms".into(),
                id: "3059".into()
            })
        );
        assert_eq!(measured(&events[..1]), None);
        let twice = [events[1].clone(), events[1].clone()];
        assert_eq!(measured(&twice), None);
    }

    #[test]
    fn empty_pin_is_kept() {
        assert_eq!(pinned(r#"{"key_provider_id":""}"#), Some(String::new()));
        assert_eq!(pinned(r#"{"name":"x"}"#), None);
        assert_eq!(pinned("not json"), None);
    }
}
