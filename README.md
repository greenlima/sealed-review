# sealed-review

An independent review of confidential-AI releases. A watcher fetches a provider's attestation report with
its own nonce and checks it link by link: the Intel TDX quote against collateral fetched directly from
Intel, the measured boot against the published OS image, the event log, the app's compose, the launcher
log, the TLS and OHTTP keys, and the GPUs through NVIDIA's attestation service. The result is a signed
verdict. Verdicts form a hash-chained feed, mirrored to a NEAR testnet contract that checks every
signature itself, and a gate sends a request only to a machine the current verdict reviewed. What each
check requires, how checks become a verdict, and what a verdict does not cover: [METHOD.md](METHOD.md).

The first subject is NEAR AI's GLM 5.3 Flash, reached directly and through NEAR's gateway, where the gate
also encrypts each request end to end to a model key the verdict reviewed. This repository is our entry in the NEAR hackathon
(tracks: Privacy & Private AI, AI Security & Defense). NEAR, a provider the feed reviews, pays the
hackathon's prizes; see [Independence](METHOD.md#independence).

Licensed under the [Apache License 2.0](LICENSE).

## Why an independent review

A confidential-AI provider usually runs the hardware and also issues the evidence that the hardware runs
the code it claims, so its users take the provider's word for it. Sweden's data protection authority
describes this in its final report on trusted execution environments ([IMY-2026-5444](https://www.imy.se/en/publications/betrodda-exekveringsmiljoer-for-uppkopplade-fordon/),
section 3.3.1): in conventional cloud set-ups "users of the environment must largely rely on the provider's
own assurances and security guarantees"; the attestation function "could also be organised through an
independent third party", which "could further strengthen the independence of the function"; and "[t]he
more frequently attestations are performed, the more rapidly any deviations affecting the integrity of
the system can be detected". sealed-review is such a third party for NEAR AI: it checks every machine its
repeated fetches reach, publishes the results signed, and lets a client act on them on its own machine.
The report comes from IMY's data protection innovation sandbox with Volvo Group, CanaryBit and Ericsson, on
trucks' camera and sensor data rather than AI, and is guidance, not a ruling; its English text is an
automatic translation, and the Swedish version applies.

## What you need

- Rust 1.92 or later for the watcher; Rust 1.99.1 for the mirror contract (pinned in
  `mirror/rust-toolchain.toml`, installed by rustup on first use).
- Network access to the model endpoint, NEAR's endpoint registry (`completions.near.ai`), NEAR's gateway (`cloud-api.near.ai`), Intel's PCS, NVIDIA's attestation service, GitHub (for the dstack
  OS image) and the two NEAR testnet RPC providers named below.

## 1. Build and test

```sh
cargo build --release -p watcher
cargo test -p watcher
```

See: the binary at `target/release/watcher`; every test passes without network access.

## 2. Review the live endpoint

```sh
alias watcher=target/release/watcher
watcher fetch --out near
```

See: one line per machine reached (its TLS key, then `ok` or what is missing), then a summary such as
`1 machine(s) in 5 fetch(es): 1 new, 0 seen again; 0 kept from earlier sweeps, 0 dropped (24 h old); 1 machine(s) in near`.
Fetching stops after 4 fetches in a row reach no new machine. Each machine's evidence is saved as
`near/machine-N.json`. Running `fetch` again refreshes the machines it reaches again (`seen again`) and
adds new ones; evidence 24 hours old drops out.

```sh
watcher image near/machine-1.json
watcher check near/machine-1.json
```

See: the published dstack OS image fetched into `~/.cache/sealed-review/images`, checked against the hash
the report declares; then the review as JSON. It contains the release's facts, one entry per check, each
with its link of the chain, its status (`pass`, `warn`, `fail`, `unknown`) and the reason, and the overall
`tier` (`affirming`, `warning`, `contraindicated` or `none`).

```sh
cp near/machine-1.json near/before.json
watcher fetch --out near
watcher diff near/before.json near/machine-1.json
```

See: what differs between two saved bundles (facts, check statuses, tier, launcher log) and whether they
are the same instance. Any two bundles of one endpoint work: two machines of one sweep, or a copy kept
from an earlier sweep and the same machine fetched again after a new release.

## 2b. Review the route through NEAR's gateway

```sh
watcher gateway fetch --out gateway.json
watcher gateway image gateway.json
watcher gateway check gateway.json --direct near
```

See: `<instance>: N candidate machine(s); saved gateway.json`, then the OS images of the gateway and of
each candidate, then the route's review as JSON: the gateway machine's checks, each candidate's, and the
route's own two checks. The route is at most `warning`, because no client can see which machine the gateway
forwards to (`forwarding_observable`). Each candidate must be a machine the direct sweep in `near` reached
within 24 hours (`reached_directly`).

## 3. Verify the signed feed

The feed has two public keys, `feed-public-a.pem` and `feed-public-b.pem`, each generated on its own
YubiKey; key A signs, key B is kept offline. Entries are `feed/000001.jwt`, `feed/000002.jwt`, …, each an
EAT Attestation Result (EAR) signed ES256 by one of the keys and chained to the previous entry by its SHA-256.
If a YubiKey is lost, the other key signs an entry that retires its key; entries signed by a retired key
are refused from then on.

Each YubiKey attests its key: a certificate saying the key was generated inside it, signed by a key Yubico
put in the YubiKey at the factory (`feed-attestation-f9-a.pem`), which chains to Yubico's root.

```sh
curl -sSO https://developers.yubico.com/PKI/yubico-ca-1.pem
curl -sSO https://developers.yubico.com/PKI/yubico-intermediate.pem
for k in a b; do
  cat feed-attestation-f9-$k.pem yubico-intermediate.pem > chain-$k.pem
  openssl verify -CAfile yubico-ca-1.pem -untrusted chain-$k.pem feed-attestation-$k.pem
  openssl x509 -in feed-attestation-$k.pem -noout -pubkey | diff - feed-public-$k.pem && echo "key $k: same key"
  openssl asn1parse -in feed-attestation-$k.pem | grep -A1 '41482\.3\.8' | tail -1
done
```

See: `OK` for each attestation, `same key`, and `0302`: the YubiKey asks for the PIN (03) and a touch (02)
before every signature. Each attestation also records its YubiKey's firmware (`41482.3.3`) and serial
number (`41482.3.7`); the two serial numbers differ, so the keys are on two devices.

```sh
watcher verify --feed feed --key feed-public-a.pem --key feed-public-b.pem
```

See: the current verdict per host as JSON, with its sequence number, status, expiry, any correction and
the TLS keys of the machines it reviewed. The gateway route is named `cloud-api.near.ai/z-ai/glm-5.3-flash`;
its only TLS key is the gateway machine's, and its `model_keys` are the candidates' keys a request may be
encrypted to. `keys` lists both keys and the entry that retired a key, if any. Changing one byte of any
entry makes `verify` fail.

## 4. Compare the feed with its NEAR testnet mirror

```sh
watcher mirror --contract sealed-review-feed.testnet --feed feed --key feed-public-a.pem --key feed-public-b.pem
```

See: the mirror read from `test.rpc.fastnear.com` and `archival-rpc.testnet.near.org` at one block height,
both providers agreeing, the contract locked (no access keys), holding the feed's two keys, and in sync with
`feed/`.

## 5. Gate a request

```sh
watcher gate --contract sealed-review-feed.testnet --key feed-public-a.pem --key feed-public-b.pem
```

See: whether a request to the host may be sent, and to which machines. Only an unexpired `affirming`
verdict passes; `--accept warning` also lets `warning` through.

```sh
NEARAI_API_KEY=... watcher ask --contract sealed-review-feed.testnet --key feed-public-a.pem --key feed-public-b.pem --prompt "Hello"
```

See: the model's answer and the TLS key of the machine that served it. The gate checks the server's key
during the TLS handshake, so no request byte reaches a machine the verdict did not review.

```sh
NEARAI_API_KEY=... watcher ask --contract sealed-review-feed.testnet --key feed-public-a.pem --key feed-public-b.pem --accept warning \
  --host cloud-api.near.ai/z-ai/glm-5.3-flash --prompt "Hello"
```

See: the same through the gateway, plus `end-to-end encrypted to model key …`. The prompt leaves your
machine encrypted to a reviewed model key, and an answer that does not decrypt to this request's key is
refused. What this does and does not hide: [METHOD.md](METHOD.md#what-passing-the-gate-means).

## 6. The mirror contract

```sh
cd mirror
cargo test
```

See: the contract's tests pass. The contract accepts an entry from anyone, but only if one of the two feed
keys signed it (low-S), that key is not retired, and the entry follows the current head.

Then check that the contract on testnet is this code. Its account has no keys left, so nobody can change it.
Ask it which commit it was built from, build that commit in the Docker image pinned by digest in
`mirror/Cargo.toml`, and compare the checksum with the deployed one:

```sh
rpc() { curl -s https://test.rpc.fastnear.com -H 'Content-Type: application/json' -d "$1"; }
rpc '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function","finality":"final","account_id":"sealed-review-feed.testnet","method_name":"contract_source_metadata","args_base64":"e30="}}' \
  | jq '.result.result | implode | fromjson | .build_info'
git checkout <rev from source_code_snapshot>
cargo near build reproducible-wasm
rpc '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"final","account_id":"sealed-review-feed.testnet"}}' \
  | jq -r .result.code_hash
rpc '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_access_key_list","finality":"final","account_id":"sealed-review-feed.testnet"}}' \
  | jq '.result.keys | length'
```

See: `build_info` names the image digest and `git+https://github.com/greenlima/sealed-review.git?rev=…`; the
build prints a `SHA-256 checksum bs58` equal to the deployed `code_hash`; and the account has `0` keys.

## 7. Side by side with NEAR's own SDK

```sh
cd compare
cargo run -- ../near/machine-1.json
```

See: NEAR's Rust SDK run on the same evidence as the watcher, on its defaults and on a strict policy, and
for each case whether the two agree.
