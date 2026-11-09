# For coding agents

What this repository claims, where each claim is implemented, and the command or test that shows it.
[METHOD.md](METHOD.md) is the specification; where it and the code differ, the code decides and the page is
corrected. [README.md](README.md) has every command with what it prints. The project is Countersign;
`sealed-review` names its repository, its NEAR accounts (`sealed-review-feed.testnet`), the watcher's user
agent and the policy id in each entry, which the locked contract and the signed entries keep.

## Layout

| Path | What it is |
| --- | --- |
| `watcher/` | The command-line watcher (Rust, the workspace's only member): fetch, check, diff, draft, seal, verify, mirror, gate, ask, gateway |
| `mirror/` | The NEAR testnet contract (its own crate, `near-sdk`, toolchain pinned in `mirror/rust-toolchain.toml`) |
| `compare/` | NEAR's own Rust SDK run on the same evidence as the watcher (its own crate) |
| `feed/` | The signed entries `000001.jwt`, `000002.jwt`, … |
| `feed-public-{a,b}.pem` | The feed's two P-256 public keys |
| `feed-attestation-*.pem` | Each YubiKey's attestation of its key, and the certificate that signed it |
| `.github/workflows/check.yml` | The daily public check of the feed and its mirror |

## What each command needs

| Needs | Commands |
| --- | --- |
| crates.io, once | `cargo build --release -p watcher` |
| Nothing | `cargo test -p watcher`; `watcher verify`; `watcher check` and `watcher diff` on a saved bundle once `watcher image` has cached its OS image |
| Read-only NEAR testnet RPC (`test.rpc.fastnear.com`, `archival-rpc.testnet.near.org`) | `watcher mirror`, `watcher gate` |
| NEAR AI's endpoints, Intel PCS, NVIDIA's attestation service and GitHub; no key | `watcher fetch`, `watcher image`, `watcher gateway fetch`, `watcher gateway image` |
| rustup (toolchain download) | `cd mirror && cargo test` |
| Docker | `cd mirror && cargo near build reproducible-wasm` |
| A NEAR AI API key in `NEARAI_API_KEY` | `watcher ask` |
| The author's YubiKey and relay account; not needed to review | signing a draft, and the `near` command that appends an entry |

`watcher fetch --host <model host>` and `watcher gateway fetch --model <model id>` review another model NEAR
AI serves in a TEE; both default to GLM 5.3 Flash, the only model this repository's feed covers.

`watcher draft`, `correct` and `retire` write an unsigned draft into `feed/`; reviewing does not need them.

## Exit status

- `verify`: 0 with the current verdict per host as JSON; non-zero if any entry fails to verify.
- `mirror`: 0 when the report says `"ok": true`; non-zero when the providers disagree, the contract has
  access keys, holds other keys, or is not in sync with `feed/`.
- `gate`: 0 with the machines a request may go to; 1 with `refused: …` and every reason when the current
  verdict does not pass, for example a `warning` without `--accept warning`, or an expired verdict. A
  refusal is the gate working.
- `check`: 0 with the review as JSON, whatever the tier. Without the OS image in the cache, `os_image` and
  `measurements` are `unknown`, so the tier is `none`; run `watcher image <bundle>` first.

## Claims, code and evidence

| Claim | Code | Shown by |
| --- | --- | --- |
| A verdict is fail-closed: any fail is `contraindicated`; a required check missing, duplicated or unknown gives `none`; any warn gives `warning` | `watcher/src/verdict.rs` (`tier`) | tests `one_fail_contraindicates`, `missing_required_is_none`, `duplicated_required_is_none`, `unknown_required_is_none`, `warn_lowers_to_warning` |
| The TDX quote is verified with collateral fetched from Intel at fetch time, compared with Intel's early stream and a second source | `watcher/src/quote.rs` | checks `quote_signature`, `tcb_status`, `collateral_early`, `collateral_second_opinion` in `watcher check` |
| MRTD and RTMR0–2 are recomputed from the published OS image, fetched and checked against its declared hash | `watcher/src/image.rs`, `watcher/src/measure.rs` | checks `os_image`, `measurements` |
| The event log replays to all four RTMRs, and every application event recomputes | `watcher/src/events.rs` | checks `rtmr_replay`, `rtmr3_events` |
| No debug or unexpected TD attribute; CPU features match the image's record | `watcher/src/attributes.rs` | checks `td_attributes`, `xfam` |
| The quote binds our nonce, the signing key and the TLS key of the connection that returned the report; MRCONFIGID carries the compose hash | `watcher/src/binding.rs`, `watcher/src/fetch.rs` | checks `nonce_fresh`, `signer_bound`, `tls_bound`, `config_measured` |
| An offered OHTTP key is signed by the bound key | `watcher/src/ohttp.rs` | check `ohttp_key_bound` |
| The launcher's action log recomputes, carries our nonce and is quoted by the same machine | `watcher/src/launcher.rs` | check `launcher_log_bound` |
| NVIDIA's tokens are verified locally against pinned NVIDIA keys, and every declared GPU is affirmed with our nonce | `watcher/src/gpu.rs` | checks `gpu`, `nvswitch` (`no_gpus` for the gateway machine) |
| The model named is one NEAR's registry lists for the host | `watcher/src/registry.rs` | check `model_registered` |
| The gateway route is at most `warning`; each candidate must be a machine reached directly; the gateway's compose pins every image | `watcher/src/gateway.rs`, `watcher/src/compose.rs` | checks `forwarding_observable`, `reached_directly`, `model_requested`, `compose_pinned`; test `a_gateway_entry_pins_only_the_gateway` |
| Entries are ES256 EARs, low-S, hash-chained, signed by one of two keys, with retirement, expiry and corrections | `watcher/src/feed.rs` | tests `entries_chain_and_verify`, `a_changed_entry_fails`, `a_removed_entry_breaks_the_chain`, `another_key_is_refused`, `signatures_are_low_s`, `a_retired_key_is_refused`, `a_key_cannot_retire_itself_or_a_stranger`, `old_evidence_is_refused`, `a_correction_replaces_the_status` |
| The contract checks the signature, the key and the chain of every entry itself | `mirror/src/lib.rs` | tests `a_changed_entry_is_refused`, `a_high_s_signature_is_refused`, `a_gap_is_refused`, `a_replayed_entry_is_refused`, `a_retired_key_is_refused`, `watcher_entries_are_accepted` |
| The mirror is read from two providers at one block, and is locked, holds the feed's keys and matches `feed/` | `watcher/src/mirror.rs` | `watcher mirror` fields `agree`, `locked`, `same_keys`, `standing`; test `feed_against_mirror` |
| Other contracts and apps can read each host's current verdict from the mirror | `mirror/src/lib.rs` | views `hosts`, `latest(host)`; tests `entries_chain`, `a_correction_replaces_the_status` |
| The deployed contract is this source | `mirror/Cargo.toml` (reproducible build) | README step 6: the build's checksum equals the deployed `code_hash` |
| The gate checks the server's TLS key during the handshake, so an unreviewed machine receives no request byte | `watcher/src/gate.rs` | tests `nothing_is_sent_to_an_unreviewed_machine`, `a_reviewed_machine_is_asked`, `a_warning_passes_only_when_accepted`, `every_reason_is_given`, `a_passed_warning_carries_its_reasons` |
| Through the gateway, the prompt is encrypted end to end to a reviewed model key and an answer that does not decrypt is refused | `watcher/src/e2ee.rs` | tests `a_request_matches_the_reference`, `an_answer_from_the_reference_opens`, `a_changed_or_plain_answer_is_refused`, `a_bad_model_key_is_refused` |
| Each feed key was generated on its own YubiKey, which needs a PIN and a touch to sign | `feed-attestation-*.pem` | README step 3: `openssl verify` against Yubico's root, and the policy bytes `0302` |
| The evidence behind each entry is published | GitHub release `feed-<seq>` | README step 3b: the nonces and fetch times in the entry are found in the bundles |
| The feed and the mirror are checked in public every day | `.github/workflows/check.yml` | the repository's Actions tab |
| What the watcher adds to NEAR's own verifier | `compare/src/main.rs` | README step 7 |

## Not claimed

The limits are in [METHOD.md](METHOD.md#what-a-verdict-does-not-say). In short: who built each container
image is not checked; key release is not judged; response signatures are not checked; a verdict covers only
the machines reached in the last 24 hours; and through the gateway no client can see which machine serves
a request.
