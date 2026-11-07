use crate::verdict::{Check, Status};

/// Mounts or settings that let a container start or change other containers.
const CONTROL: [&str; 3] = ["docker.sock", "/var/run:/var/run", "privileged: true"];

#[derive(Debug, Default, PartialEq, Eq)]
struct Service {
    name: String,
    images: Vec<String>,
    controls: bool,
}

/// A line scan of the `services:` block, enough for dstack's generated compose files.
fn services(yaml: &str) -> Vec<Service> {
    let mut found: Vec<Service> = Vec::new();
    let mut inside = false;
    let mut indent_of_service = None;
    for line in yaml.lines() {
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            inside = text == "services:";
            continue;
        }
        if !inside {
            continue;
        }
        let service_indent = *indent_of_service.get_or_insert(indent);
        if indent == service_indent {
            found.push(Service {
                name: text.trim_end_matches(':').to_owned(),
                ..Service::default()
            });
            continue;
        }
        let Some(service) = found.last_mut() else {
            continue;
        };
        if let Some(image) = text.strip_prefix("image:") {
            service
                .images
                .push(image.trim().trim_matches('"').to_owned());
        }
        service.controls |= CONTROL.iter().any(|c| text.contains(c));
    }
    found
}

fn appraise(app_compose: &str) -> (Status, String) {
    let Some(yaml) = serde_json::from_str::<serde_json::Value>(app_compose)
        .ok()
        .and_then(|c| c.get("docker_compose_file")?.as_str().map(str::to_owned))
    else {
        return (
            Status::Unknown,
            "app_compose has no docker_compose_file".into(),
        );
    };
    let services = services(&yaml);
    if services.is_empty() {
        return (
            Status::Unknown,
            "no services found in the compose file".into(),
        );
    }
    let unpinned: Vec<&str> = services
        .iter()
        .flat_map(|s| &s.images)
        .filter(|i| !i.contains("@sha256:"))
        .map(String::as_str)
        .collect();
    if !unpinned.is_empty() {
        return (
            Status::Fail,
            format!("images not pinned by digest: {}", unpinned.join(", ")),
        );
    }
    let controlling: Vec<&str> = services
        .iter()
        .filter(|s| s.controls)
        .map(|s| s.name.as_str())
        .collect();
    if controlling.is_empty() {
        return (
            Status::Pass,
            format!("{} services, every image pinned by digest", services.len()),
        );
    }
    (
        Status::Warn,
        format!(
            "every image pinned by digest, but {} can start or change containers (Docker socket or \
             privileged) and no launcher log records what they start",
            controlling.join(", ")
        ),
    )
}

/// Link 7 for a machine without a launcher: the compose is all that runs only if every image is
/// pinned and no service can start others.
pub fn check(app_compose: &str) -> Check {
    let (status, detail) = appraise(app_compose);
    Check::new(7, "compose_pinned", status, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compose(yaml: &str) -> String {
        serde_json::json!({ "docker_compose_file": yaml }).to_string()
    }

    const PINNED: &str = "services:\n  api:\n    image: org/api@sha256:aa\n    volumes:\n      - /data:/data\nconfigs:\n  c:\n    content: unix:///var/run/docker.sock\n";

    #[test]
    fn pinned_without_control_passes() {
        assert_eq!(appraise(&compose(PINNED)).0, Status::Pass);
    }

    #[test]
    fn unpinned_image_fails() {
        let yaml = PINNED.replace("org/api@sha256:aa", "org/api:latest");
        assert_eq!(appraise(&compose(&yaml)).0, Status::Fail);
    }

    #[test]
    fn docker_socket_warns_and_names_the_service() {
        let yaml = PINNED.replace(
            "/data:/data",
            "/var/run/docker.sock:/var/run/docker.sock:ro",
        );
        let (status, detail) = appraise(&compose(&yaml));
        assert_eq!(status, Status::Warn);
        assert!(detail.contains("api can start"));
    }

    #[test]
    fn services_are_read_from_the_services_block_only() {
        let found = services(PINNED);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].images, ["org/api@sha256:aa"]);
        assert!(!found[0].controls);
    }

    #[test]
    fn unreadable_compose_is_unknown() {
        assert_eq!(appraise("{}").0, Status::Unknown);
        assert_eq!(appraise(&compose("version: '3'\n")).0, Status::Unknown);
    }
}
