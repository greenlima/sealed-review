use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::fetch::{USER_AGENT, capped};

/// Read and compared, so one provider cannot show a different mirror.
pub const RPCS: [&str; 2] = ["test.rpc.fastnear.com", "archival-rpc.testnet.near.org"];
/// The contract returns at most this many entries per call.
const PAGE: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub sha256: String,
}

/// What one provider says about the contract at the shared block height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct State {
    pub code_hash: String,
    /// Access keys on the contract account; none means nobody can change its code.
    pub keys: usize,
    /// The feed keys the contract was created with, sorted.
    pub kids: Vec<String>,
    pub head: Option<Head>,
}

#[derive(Deserialize)]
struct FeedKey {
    kid: String,
}

#[derive(Debug, Serialize)]
pub struct Provider {
    pub rpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip)]
    entries: Vec<String>,
}

/// Both providers' answers at one block height, and the contract's state and entries if they agree.
pub struct Observation {
    pub height: u64,
    pub providers: Vec<Provider>,
    pub agreed: Option<(State, Vec<String>)>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Standing {
    InSync,
    /// The mirror lacks these entries of the feed; anyone may append them.
    Behind {
        missing: Vec<u64>,
    },
    /// The mirror holds entries this feed lacks: the feed shown here is old or cut short.
    Ahead {
        mirror: u64,
        feed: u64,
    },
    /// The mirror's head differs from the feed's entry with the same sequence number.
    Forked {
        seq: u64,
    },
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub contract: String,
    pub height: u64,
    pub providers: Vec<Provider>,
    pub agree: bool,
    pub locked: bool,
    pub same_keys: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standing: Option<Standing>,
    pub ok: bool,
}

/// Where the feed stands against the mirror's head. Each entry names the hash of the one before,
/// so equal hashes at the head's sequence number mean equal histories up to it.
pub fn compare(mirror: Option<&Head>, local: &[String]) -> Standing {
    let feed = local.len() as u64;
    let Some(head) = mirror else {
        return match feed {
            0 => Standing::InSync,
            _ => Standing::Behind {
                missing: (1..=feed).collect(),
            },
        };
    };
    if head.seq > feed {
        return Standing::Ahead {
            mirror: head.seq,
            feed,
        };
    }
    let matches = head
        .seq
        .checked_sub(1)
        .and_then(|i| local.get(i as usize))
        .is_some_and(|h| *h == head.sha256);
    match (matches, head.seq == feed) {
        (false, _) => Standing::Forked { seq: head.seq },
        (true, true) => Standing::InSync,
        (true, false) => Standing::Behind {
            missing: (head.seq + 1..=feed).collect(),
        },
    }
}

pub fn valid_account(id: &str) -> bool {
    (2..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

async fn call(client: &reqwest::Client, rpc: &str, method: &str, params: Value) -> Result<Value> {
    let body =
        json!({ "jsonrpc": "2.0", "id": "sealed-review", "method": method, "params": params });
    let response = client
        .post(format!("https://{rpc}/"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?
        .error_for_status()?;
    let mut answer: Value = serde_json::from_str(&capped(response).await?)?;
    if let Some(error) = answer.get("error") {
        bail!("{error}");
    }
    let result = answer["result"].take();
    if let Some(error) = result.get("error") {
        bail!("{error}");
    }
    Ok(result)
}

async fn final_height(client: &reqwest::Client, rpc: &str) -> Result<u64> {
    let block = call(client, rpc, "block", json!({ "finality": "final" }))
        .await
        .with_context(|| format!("{rpc}: latest final block"))?;
    block["header"]["height"]
        .as_u64()
        .with_context(|| format!("{rpc}: block: no height"))
}

struct At<'a> {
    client: &'a reqwest::Client,
    rpc: &'a str,
    contract: &'a str,
    height: u64,
}

impl At<'_> {
    async fn query(&self, request: &str) -> Result<Value> {
        let params = json!({ "request_type": request, "block_id": self.height, "account_id": self.contract });
        call(self.client, self.rpc, "query", params).await
    }

    async fn view<T: DeserializeOwned>(&self, method: &str, args: Value) -> Result<T> {
        let params = json!({
            "request_type": "call_function",
            "block_id": self.height,
            "account_id": self.contract,
            "method_name": method,
            "args_base64": STANDARD.encode(serde_json::to_vec(&args)?),
        });
        let result = call(self.client, self.rpc, "query", params).await?;
        let bytes: Vec<u8> = serde_json::from_value(result["result"].clone())
            .with_context(|| format!("{method}: no result bytes"))?;
        serde_json::from_slice(&bytes).with_context(|| format!("{method}: unexpected answer"))
    }

    async fn read(&self) -> Result<(State, Vec<String>)> {
        let (account, keys, feed_keys, head, mut entries) = tokio::try_join!(
            self.query("view_account"),
            self.query("view_access_key_list"),
            self.view::<Vec<FeedKey>>("feed_keys", json!({})),
            self.view::<Option<Head>>("head", json!({})),
            self.view::<Vec<String>>("entries", json!({ "from": 1, "limit": PAGE })),
        )?;
        let count = head.as_ref().map_or(0, |h| h.seq);
        for from in (1 + PAGE..=count).step_by(PAGE as usize) {
            let page: Vec<String> = self
                .view("entries", json!({ "from": from, "limit": PAGE }))
                .await?;
            entries.extend(page);
        }
        ensure!(
            entries.len() as u64 == count,
            "{count} entries announced, {} returned",
            entries.len()
        );
        let state = State {
            code_hash: account["code_hash"]
                .as_str()
                .context("view_account: no code_hash")?
                .to_owned(),
            keys: keys["keys"]
                .as_array()
                .context("view_access_key_list: no keys")?
                .len(),
            kids: sorted(feed_keys.into_iter().map(|k| k.kid).collect()),
            head,
        };
        Ok((state, entries))
    }
}

async fn provider(
    client: &reqwest::Client,
    rpc: &'static str,
    contract: &str,
    height: u64,
) -> Provider {
    let at = At {
        client,
        rpc,
        contract,
        height,
    };
    match at.read().await {
        Ok((state, entries)) => Provider {
            rpc,
            state: Some(state),
            error: None,
            entries,
        },
        Err(e) => Provider {
            rpc,
            state: None,
            error: Some(format!("{e:#}")),
            entries: Vec::new(),
        },
    }
}

/// Reads the contract and all its entries from both providers at once, at the lower of their final heights.
pub async fn observe(contract: &str) -> Result<Observation> {
    ensure!(
        valid_account(contract),
        "{contract} is not a NEAR account id"
    );
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()?;
    let [one, two] = RPCS;
    let (h1, h2) = tokio::try_join!(final_height(&client, one), final_height(&client, two))?;
    let height = h1.min(h2);
    let (p1, p2) = tokio::join!(
        provider(&client, one, contract, height),
        provider(&client, two, contract, height)
    );
    let providers = vec![p1, p2];
    let first = &providers[0];
    let agree = first.state.is_some()
        && providers
            .iter()
            .all(|p| p.state == first.state && p.entries == first.entries);
    let agreed = first
        .state
        .clone()
        .filter(|_| agree)
        .map(|s| (s, first.entries.clone()));
    Ok(Observation {
        height,
        providers,
        agreed,
    })
}

pub fn sorted(mut kids: Vec<String>) -> Vec<String> {
    kids.sort();
    kids
}

/// The mirror against a local feed's keys and entry hashes.
pub async fn check(contract: &str, kids: Vec<String>, local: &[String]) -> Result<Report> {
    let kids = sorted(kids);
    let Observation {
        height,
        providers,
        agreed,
    } = observe(contract).await?;
    let state = agreed.map(|(s, _)| s);
    let locked = state.as_ref().is_some_and(|s| s.keys == 0);
    let same_keys = state.as_ref().is_some_and(|s| s.kids == kids);
    let standing = state.as_ref().map(|s| compare(s.head.as_ref(), local));
    let ok = locked && same_keys && standing == Some(Standing::InSync);
    Ok(Report {
        contract: contract.to_owned(),
        height,
        providers,
        agree: state.is_some(),
        locked,
        same_keys,
        standing,
        ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("{i:064x}")).collect()
    }

    fn head(seq: u64, sha256: String) -> Head {
        Head { seq, sha256 }
    }

    #[test]
    fn feed_against_mirror() {
        let feed = local(3);
        assert_eq!(compare(None, &[]), Standing::InSync);
        assert_eq!(
            compare(None, &feed),
            Standing::Behind {
                missing: vec![1, 2, 3]
            }
        );
        assert_eq!(
            compare(Some(&head(3, feed[2].clone())), &feed),
            Standing::InSync
        );
        assert_eq!(
            compare(Some(&head(1, feed[0].clone())), &feed),
            Standing::Behind {
                missing: vec![2, 3]
            }
        );
        assert_eq!(
            compare(Some(&head(4, "ff".into())), &feed),
            Standing::Ahead { mirror: 4, feed: 3 }
        );
        assert_eq!(
            compare(Some(&head(2, feed[0].clone())), &feed),
            Standing::Forked { seq: 2 }
        );
        assert_eq!(
            compare(Some(&head(0, String::new())), &feed),
            Standing::Forked { seq: 0 }
        );
    }

    #[test]
    fn account_ids() {
        assert!(valid_account("feed-mirror.testnet"));
        assert!(!valid_account("Feed.testnet"));
        assert!(!valid_account("a\"b.testnet"));
        assert!(!valid_account("x"));
    }
}
