use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use serde_json::Value;

use crate::feed::{Current, Feed, HeadRef, Keys};
use crate::fetch::{USER_AGENT, capped, spki_sha256};
use crate::mirror::{self, State};
use crate::verdict::Tier;

/// Fresh connections tried to reach a machine the verdict reviewed.
pub const TRIES: u32 = 4;

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub accept_warning: bool,
}

impl Policy {
    fn passes(self, status: Tier) -> bool {
        status == Tier::Affirming || (self.accept_warning && status == Tier::Warning)
    }
}

/// The verdict a request may rest on.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Pass {
    pub seq: u64,
    pub status: Tier,
    pub exp: u64,
    pub corrected_by: Option<u64>,
    pub tls_keys: Vec<String>,
    /// For a gateway route, the reviewed model keys whose status the policy accepts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub model_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Admission {
    pub host: String,
    pub contract: String,
    pub height: u64,
    #[serde(flatten)]
    pub pass: Pass,
}

/// Every reason the mirror's state and the host's current verdict refuse a request; none means it passes.
pub fn decide(
    state: &State,
    kids: &[String],
    feed_head: Option<&HeadRef>,
    current: Option<&Current>,
    policy: Policy,
) -> std::result::Result<Pass, Vec<String>> {
    let mut reasons = Vec::new();
    if state.keys != 0 {
        reasons.push(format!(
            "the mirror contract is not locked: {} access key(s)",
            state.keys
        ));
    }
    if state.kids != mirror::sorted(kids.to_vec()) {
        reasons.push(format!(
            "the mirror holds feed keys {}, not {}",
            state.kids.join(", "),
            kids.join(", ")
        ));
    }
    let announced = state.head.as_ref().map(|h| (h.seq, h.sha256.as_str()));
    if announced != feed_head.map(|h| (h.seq, h.sha256.as_str())) {
        reasons.push("the mirror's entries do not end at its announced head".into());
    }
    let Some(current) = current else {
        reasons.push("the feed has no verdict for this host".into());
        return Err(reasons);
    };
    if current.expired {
        reasons.push(format!(
            "verdict {} expired at {}",
            current.seq, current.exp
        ));
    }
    if !policy.passes(current.status) {
        let hint = match current.status {
            Tier::Warning => "; pass --accept warning to accept it",
            _ => "",
        };
        reasons.push(format!(
            "verdict {} is {}{hint}",
            current.seq,
            serde_json::to_value(current.status).unwrap_or_default()
        ));
    }
    if current.tls_keys.is_empty() {
        reasons.push(format!("verdict {} reviewed no machine", current.seq));
    }
    let model_keys: Vec<String> = current
        .model_keys
        .iter()
        .filter(|k| policy.passes(k.status))
        .map(|k| k.key.clone())
        .collect();
    if connect(&current.host).1.is_some() && model_keys.is_empty() {
        reasons.push(format!(
            "verdict {} has no accepted model key to encrypt a request to",
            current.seq
        ));
    }
    if !reasons.is_empty() {
        return Err(reasons);
    }
    Ok(Pass {
        seq: current.seq,
        status: current.status,
        exp: current.exp,
        corrected_by: current.corrected_by,
        tls_keys: current.tls_keys.clone(),
        model_keys,
    })
}

/// Where a client connects for a feed name, and the model a gateway route is for: a gateway
/// route is named `<host>/<model id>`, and model ids hold `/` themselves.
pub fn connect(name: &str) -> (&str, Option<&str>) {
    match name.split_once('/') {
        Some((host, model)) => (host, Some(model)),
        None => (name, None),
    }
}

/// Reads the feed from the mirror through both providers, verifies it and decides for `host`.
pub async fn gate(
    host: &str,
    contract: &str,
    keys: Keys,
    policy: Policy,
    now: u64,
) -> Result<Admission> {
    let kids = keys.kids();
    let observed = mirror::observe(contract).await?;
    let Some((state, entries)) = observed.agreed else {
        let errors: Vec<String> = observed
            .providers
            .iter()
            .filter_map(|p| p.error.as_ref().map(|e| format!("{}: {e}", p.rpc)))
            .collect();
        bail!(
            "refused: the providers do not agree on the mirror at block {} ({})",
            observed.height,
            errors.join("; ")
        );
    };
    let feed =
        Feed::from_entries(entries, keys).context("refused: the mirror's entries do not verify")?;
    let summary = feed.summary(now);
    let current = summary.current.iter().find(|c| c.host == host);
    match decide(&state, &kids, summary.head.as_ref(), current, policy) {
        Ok(pass) => Ok(Admission {
            host: host.to_owned(),
            contract: contract.to_owned(),
            height: observed.height,
            pass,
        }),
        Err(reasons) => bail!("refused: {}", reasons.join("; ")),
    }
}

/// The usual certificate check, then the server key must be one the verdict reviewed.
#[derive(Debug)]
struct Pinned {
    inner: Arc<dyn ServerCertVerifier>,
    allowed: HashSet<String>,
    seen: Mutex<Option<String>>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let spki = spki_sha256(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("server certificate: {e}")))?;
        let reviewed = self.allowed.contains(&spki);
        *self.seen.lock().expect("lock") = Some(spki);
        if !reviewed {
            return Err(rustls::Error::General("server key was not reviewed".into()));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The system's roots, as reqwest uses them.
pub fn system_roots() -> Result<Arc<dyn ServerCertVerifier>> {
    Ok(Arc::new(rustls_platform_verifier::Verifier::new(
        provider(),
    )?))
}

#[derive(Debug)]
pub struct Answer {
    pub tls_key: String,
    pub response: Value,
}

/// Posts `request` to `{base}/v1/chat/completions` on a connection to a reviewed machine only:
/// the server key is checked in the handshake, so nothing is sent to any other.
pub async fn ask(
    base: &str,
    roots: Arc<dyn ServerCertVerifier>,
    tls_keys: &[String],
    api_key: &str,
    headers: &[(&'static str, String)],
    request: &Value,
) -> Result<Answer> {
    let body = serde_json::to_vec(request)?;
    let mut unreviewed = Vec::new();
    for _ in 0..TRIES {
        let pinned = Arc::new(Pinned {
            inner: roots.clone(),
            allowed: tls_keys.iter().cloned().collect(),
            seen: Mutex::new(None),
        });
        let tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(pinned.clone())
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(300))
            .user_agent(USER_AGENT)
            .build()?;
        let sent = headers
            .iter()
            .fold(
                client.post(format!("{base}/v1/chat/completions")),
                |post, (name, value)| post.header(*name, value),
            )
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body.clone())
            .send()
            .await;
        let seen = pinned.seen.lock().expect("lock").clone();
        let response = match (sent, seen) {
            (Ok(response), Some(seen)) if tls_keys.contains(&seen) => (response, seen),
            (Err(_), Some(seen)) if !tls_keys.contains(&seen) => {
                unreviewed.push(seen);
                continue;
            }
            (Err(e), _) => return Err(e).context("request failed"),
            (Ok(_), _) => bail!("the connection's server key was not checked"),
        };
        let (response, tls_key) = response;
        let status = response.status();
        let text = capped(response).await?;
        if !status.is_success() {
            bail!("the model answered {status}: {text}");
        }
        return Ok(Answer {
            tls_key,
            response: serde_json::from_str(&text).context("the answer is not JSON")?,
        });
    }
    bail!(
        "refused: {TRIES} connections reached only unreviewed machines ({}); nothing was sent",
        unreviewed
            .iter()
            .map(|k| k.get(..16).unwrap_or(k))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::feed::ModelKey;

    fn kids() -> Vec<String> {
        vec!["kid".into(), "other".into()]
    }

    fn state(keys: usize, kid: &str, seq: u64) -> State {
        State {
            code_hash: "code".into(),
            keys,
            kids: mirror::sorted(vec![kid.into(), "other".into()]),
            head: Some(mirror::Head {
                seq,
                sha256: "head".into(),
            }),
        }
    }

    fn head(seq: u64) -> HeadRef {
        HeadRef {
            seq,
            sha256: "head".into(),
        }
    }

    fn current(status: Tier, expired: bool) -> Current {
        Current {
            host: "model.example".into(),
            seq: 2,
            status,
            exp: 200,
            expired,
            corrected_by: None,
            tls_keys: vec!["aa".into()],
            model_keys: Vec::new(),
        }
    }

    fn route(model_key: Option<Tier>) -> Current {
        Current {
            host: "cloud-api.near.ai/z-ai/glm-5.3-flash".into(),
            model_keys: model_key
                .map(|status| ModelKey {
                    key: "cc".into(),
                    status,
                })
                .into_iter()
                .collect(),
            ..current(Tier::Warning, false)
        }
    }

    #[test]
    fn a_gateway_route_needs_an_accepted_model_key() {
        let decide = |current: &Current| {
            decide(
                &state(0, "kid", 2),
                &kids(),
                Some(&head(2)),
                Some(current),
                LENIENT,
            )
        };
        let refused = decide(&route(None)).unwrap_err();
        assert!(refused[0].contains("no accepted model key"), "{refused:?}");
        assert!(decide(&route(Some(Tier::None))).is_err());
        let pass = decide(&route(Some(Tier::Warning))).unwrap();
        assert_eq!(pass.model_keys, ["cc"]);
    }

    const STRICT: Policy = Policy {
        accept_warning: false,
    };
    const LENIENT: Policy = Policy {
        accept_warning: true,
    };

    #[test]
    fn an_affirming_verdict_passes() {
        let pass = decide(
            &state(0, "kid", 2),
            &kids(),
            Some(&head(2)),
            Some(&current(Tier::Affirming, false)),
            STRICT,
        )
        .unwrap();
        assert_eq!((pass.seq, pass.tls_keys), (2, vec!["aa".to_string()]));
    }

    #[test]
    fn the_key_set_must_match_in_any_order() {
        let affirming = current(Tier::Affirming, false);
        let decide = |kids: &[String]| {
            decide(
                &state(0, "kid", 2),
                kids,
                Some(&head(2)),
                Some(&affirming),
                STRICT,
            )
        };
        assert!(decide(&["other".into(), "kid".into()]).is_ok());
        let refused = decide(&["kid".into()]).unwrap_err();
        assert!(refused[0].contains("feed keys"), "{refused:?}");
    }

    #[test]
    fn a_gateway_route_connects_to_its_host() {
        assert_eq!(
            connect("cloud-api.near.ai/z-ai/glm-5.3-flash"),
            ("cloud-api.near.ai", Some("z-ai/glm-5.3-flash"))
        );
        assert_eq!(
            connect("glm-5-3-flash.completions.near.ai"),
            ("glm-5-3-flash.completions.near.ai", None)
        );
    }

    #[test]
    fn a_warning_passes_only_when_accepted() {
        let warning = current(Tier::Warning, false);
        let refused = decide(
            &state(0, "kid", 2),
            &kids(),
            Some(&head(2)),
            Some(&warning),
            STRICT,
        )
        .unwrap_err();
        assert!(refused[0].contains("--accept warning"), "{refused:?}");
        assert!(
            decide(
                &state(0, "kid", 2),
                &kids(),
                Some(&head(2)),
                Some(&warning),
                LENIENT
            )
            .is_ok()
        );
        for status in [Tier::None, Tier::Contraindicated] {
            let bad = current(status, false);
            assert!(
                decide(
                    &state(0, "kid", 2),
                    &kids(),
                    Some(&head(2)),
                    Some(&bad),
                    LENIENT
                )
                .is_err()
            );
        }
    }

    #[test]
    fn every_reason_is_given() {
        let refused = decide(
            &state(1, "third", 3),
            &kids(),
            Some(&head(2)),
            Some(&current(Tier::Affirming, true)),
            LENIENT,
        )
        .unwrap_err();
        assert_eq!(refused.len(), 4, "{refused:?}");
        let none = decide(&state(0, "kid", 2), &kids(), Some(&head(2)), None, LENIENT).unwrap_err();
        assert_eq!(none, ["the feed has no verdict for this host"]);
    }

    struct Server {
        base: String,
        roots: Arc<dyn ServerCertVerifier>,
        tls_key: String,
        connections: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
    }

    /// A local TLS server under a throwaway CA, answering one chat completion per connection.
    async fn server() -> Server {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();
        let tls_key = spki_sha256(leaf.der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("https://{}", listener.local_addr().unwrap());
        let (connections, requests) =
            (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (c, r) = (connections.clone(), requests.clone());
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                c.fetch_add(1, Ordering::SeqCst);
                let (acceptor, r) = (acceptor.clone(), r.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 16 * 1024];
                    let Ok(n) = tls.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    r.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{"choices":[{"message":{"content":"hello"}}]}"#;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        let mut store = RootCertStore::empty();
        store.add(ca.der().clone()).unwrap();
        let roots = WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider())
            .build()
            .unwrap();
        Server {
            base,
            roots,
            tls_key,
            connections,
            requests,
        }
    }

    fn request() -> Value {
        json!({ "model": "test", "messages": [{ "role": "user", "content": "hi" }] })
    }

    #[tokio::test]
    async fn a_reviewed_machine_is_asked() {
        let s = server().await;
        let answer = ask(
            &s.base,
            s.roots.clone(),
            std::slice::from_ref(&s.tls_key),
            "test-key",
            &[],
            &request(),
        )
        .await
        .unwrap();
        assert_eq!(answer.tls_key, s.tls_key);
        assert_eq!(answer.response["choices"][0]["message"]["content"], "hello");
        assert_eq!(s.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn nothing_is_sent_to_an_unreviewed_machine() {
        let s = server().await;
        let error = ask(
            &s.base,
            s.roots.clone(),
            &["00".repeat(32)],
            "test-key",
            &[],
            &request(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("nothing was sent"), "{error}");
        assert!(error.contains(&s.tls_key[..16]), "{error}");
        assert_eq!(s.connections.load(Ordering::SeqCst), TRIES as usize);
        assert_eq!(s.requests.load(Ordering::SeqCst), 0);
    }
}
