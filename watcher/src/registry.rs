use anyhow::Result;
use serde::Deserialize;

use crate::fetch::capped;
use crate::verdict::{Check, Status};

/// NEAR's list of direct model hostnames and the models each serves.
pub const URL: &str = "https://completions.near.ai/endpoints";

#[derive(Deserialize)]
struct Registry {
    endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
struct Endpoint {
    domain: String,
    models: Vec<String>,
}

/// The registry body exactly as received.
pub async fn fetch(client: &reqwest::Client) -> Result<String> {
    capped(client.get(URL).send().await?.error_for_status()?).await
}

/// The report's `model_name` is the serving machine's own claim; the quote does not cover it.
pub fn check(registry: Option<&str>, host: &str, model_name: Option<&str>) -> Check {
    let (status, detail) = appraise(registry, host, model_name);
    Check::new(5, "model_registered", status, detail)
}

fn appraise(registry: Option<&str>, host: &str, model_name: Option<&str>) -> (Status, String) {
    let Some(raw) = registry else {
        return (Status::Unknown, "no registry in the bundle".into());
    };
    let Ok(parsed) = serde_json::from_str::<Registry>(raw) else {
        return (
            Status::Unknown,
            "the registry is not a list of endpoints".into(),
        );
    };
    let Some(endpoint) = parsed.endpoints.into_iter().find(|e| e.domain == host) else {
        return (Status::Fail, format!("the registry does not list {host}"));
    };
    let listed = endpoint.models.join(", ");
    match model_name {
        Some(name) if endpoint.models.iter().any(|m| m == name) => (
            Status::Pass,
            format!("the report names {name}, listed for {host}"),
        ),
        Some(name) => (
            Status::Fail,
            format!("the report names {name}; the registry lists {listed} for {host}"),
        ),
        None => (
            Status::Fail,
            format!("the report names no model; the registry lists {listed} for {host}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = r#"{"endpoints":[
        {"domain":"a.example","models":["org/a","org/a-alias"]},
        {"domain":"b.example","models":["org/b"]}
    ]}"#;

    fn status(registry: Option<&str>, host: &str, model: Option<&str>) -> Status {
        check(registry, host, model).status
    }

    #[test]
    fn listed_model_passes() {
        assert_eq!(
            status(Some(REGISTRY), "a.example", Some("org/a-alias")),
            Status::Pass
        );
    }

    #[test]
    fn another_hosts_model_fails() {
        assert_eq!(
            status(Some(REGISTRY), "a.example", Some("org/b")),
            Status::Fail
        );
    }

    #[test]
    fn unlisted_host_fails() {
        assert_eq!(
            status(Some(REGISTRY), "c.example", Some("org/a")),
            Status::Fail
        );
    }

    #[test]
    fn report_without_model_fails() {
        assert_eq!(status(Some(REGISTRY), "b.example", None), Status::Fail);
    }

    #[test]
    fn missing_or_unreadable_registry_is_unknown() {
        assert_eq!(status(None, "a.example", Some("org/a")), Status::Unknown);
        assert_eq!(
            status(Some("[]"), "a.example", Some("org/a")),
            Status::Unknown
        );
    }
}
