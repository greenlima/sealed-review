# Review method

What a Countersign verdict checks, what it means, and what it does not cover. The code in `watcher/`
is the method: where this page and the code differ, the code decides and this page is corrected.

## What is reviewed

A **host**: one model endpoint NEAR AI serves in a TEE. The watcher takes any host or model as an option;
the feed covers GLM 5.3 Flash's direct endpoint, `glm-5-3-flash.completions.near.ai`, and the same model
through NEAR's gateway (below). Each sweep first reads NEAR's endpoint registry (`completions.near.ai/endpoints`), which names
the models each host serves. The watcher fetches its attestation report repeatedly, each time with a fresh 32-byte nonce, over TLS, and records the key of the
TLS certificate that served it. A **machine** is identified by its instance id, the SHA-256 of its app
compose and that TLS key, so a machine that changes any of the three counts as a new one. A verdict covers
every machine reached in the last 24 hours, and nothing else: other machines may serve the same host.

## The checks, link by link

Each check ends `pass`, `warn`, `fail` or `unknown`, with its reason. The links follow the order in which
trust is built, from the CPU to the keys.

| Link | Check | Passes when |
| --- | --- | --- |
| 1 Hardware root | `quote_signature`* | The TDX quote verifies against Intel's PCK certificate chain and collateral fetched from Intel at fetch time. |
| 2 Patch level | `tcb_status`* | Intel's standard collateral rates the platform `UpToDate`; `SWHardeningNeeded` warns; anything else fails. |
| | `collateral_early` | Intel's early collateral stream gives the same rating; a difference warns, since it announces the next standard rating. |
| | `collateral_second_opinion` | A second collateral source (Phala's cache) gives the same rating; a difference warns. |
| 3 What booted | `td_attributes`* | No debug, profiling or unexpected security attribute is set, reserved bits included. |
| | `xfam` | The enabled CPU features match the value recorded for this OS image; an image without a record warns. |
| | `os_image`* | The declared dstack OS image, fetched from its publisher, matches the hash the report declares. |
| | `measurements`* | MRTD and RTMR0–2 recomputed from that image for the declared VM shape equal the quote's. |
| | `rtmr_replay`* | The event log replays to all four RTMRs in the quote. |
| 4 Binding | `nonce_fresh`* | The quote's report data and the report echo our nonce. |
| | `signer_bound`* | The report's signing key, with the TLS key, is the other half of the quote's report data. |
| | `tls_bound`* | The attested TLS key is the key of the connection that returned the report. |
| | `ohttp_key_bound` | An offered OHTTP key is signed by the bound signing key. Absent when no OHTTP key is offered. |
| 5 Configuration | `config_measured`* | MRCONFIGID carries the SHA-256 of the app compose. |
| | `rtmr3_events`* | Every application event digest recomputes, and the compose and OS image events match the report. |
| | `model_registered`* | The model the report names is one NEAR's registry, read in the same sweep, lists for the host. A host the registry omits fails; a bundle without the registry is `unknown`. The name is the machine's own claim, outside the quote: this catches a host serving another model, not a machine that lies. |
| 6 Image provenance | — | Not checked yet: who built each container image, and from which source. |
| 7 Runtime changes | `launcher_log_bound`* | The launcher's action log recomputes to its hash, carries our nonce and is quoted by the same machine. |
| 8 GPUs | `gpu`* | NVIDIA's attestation service affirms every declared GPU with our nonce; its tokens are verified locally against pinned NVIDIA keys and each GPU's claims are read. |
| | `nvswitch` | No NVSwitches are declared. Declared switches without switch evidence warn: in protected PCIe mode NVIDIA attests the switches too. |
| 9 Key release | — | Not judged. Each verdict records the key service the machine measured and the one the compose pins, if any. |

\* Required: a verdict can only be `affirming` if each required check is present once and passes.

## From checks to a verdict

Fail-closed, in this order, for each machine:

1. Any `fail`: **`contraindicated`**.
2. A required check missing, duplicated or `unknown`: **`none`** (no verdict).
3. Any `warn` or `unknown`: **`warning`**.
4. Otherwise: **`affirming`**.

The host's status is its worst machine's, ranked `affirming`, `warning`, `none`, `contraindicated`.

## The gateway route

NEAR recommends its gateway, `cloud-api.near.ai`: the client connects to the gateway, which forwards each
request to a model machine it chooses. A route is named `cloud-api.near.ai/<model id>`, for example
`cloud-api.near.ai/z-ai/glm-5.3-flash`. The watcher asks the gateway for its attestation report with a
fresh nonce and no API key. The answer holds the gateway machine's own evidence and evidence for one or more
candidate model machines, each bound to the same nonce.

- **The gateway machine** gets the checks above, links 1–5, with three differences: it has no GPUs, so
  `no_gpus`* passes when none are declared and no GPU evidence is sent; it serves no model, so there is no
  `model_registered`; and it runs no launcher, so `compose_pinned`* (link 7) replaces `launcher_log_bound`:
  every image must be pinned by digest (otherwise it fails), and a service with the Docker socket or
  running privileged warns, since it can start containers that no log records.
- **Each candidate** gets the full review of a directly reached machine, except `tls_bound`: the client has
  no connection to it. Instead `reached_directly`* passes when the TLS key the candidate binds in its own
  report belongs to a machine of the same model that a direct sweep reached within 24 hours, and
  `model_requested`* passes when the candidate names the requested model.
- **The route** is at most `warning`, whatever the machines' results: a client cannot see which machine
  the gateway forwards a request to, and NEAR's documentation says the candidates are not an inventory of
  those machines. Its status is otherwise the worst of the gateway's and the candidates', and `none` if
  the answer has no candidate. Response signatures are not checked yet; a streamed answer is signed by the
  gateway only.

### The two routes, step by step

From the client's connection to the answer, as [NEAR's verification
docs](https://docs.near.ai/cloud/verification/cloud-api/gateway-attestation.md) describe the gateway and as
the watcher checks it.

| Step | Direct | Through the gateway | What a verdict says |
| --- | --- | --- | --- |
| A. The client's connection | TLS ends in the model machine, whose report binds its key | TLS ends in the gateway machine, whose report binds its key; no model machine's | `tls_bound`; the gate pins that key |
| B. The gateway machine | — | its own quote, OS image, measurements and compose | the gateway checks above |
| C. Gateway to model machine | — | the gateway checks a model machine itself and chooses it | not observable by any client; this caps the route at `warning` |
| D. Model machine evidence | the report of the machine on the connection | candidate reports, which [NEAR says](https://docs.near.ai/cloud/verification/cloud-api/model-attestations.md) are not an inventory of the machines behind the gateway | full checks; each candidate must be a machine reached directly |
| E. Who can read the prompt | the model machine | the gateway too, unless the client [encrypts end to end](https://docs.near.ai/cloud/guides/e2ee-chat-completions.md) to a model key | `watcher ask` always encrypts through the gateway (below) |
| F. Who wrote the answer | a [response signature](https://docs.near.ai/cloud/verification/cloud-api/response-signatures.md) by the model's key, shared by every machine of the model | a model signature, or the gateway's, which is the default for streamed answers and binds to the gateway only | not checked yet |
| G. Where the attested chain ends | the model machine | the model machine for NEAR's own models; NEAR's "Incognito" models run at their provider, outside a TEE | only NEAR's own model machines are reviewed |

## What a verdict is

An [EAT Attestation Result](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/) (a JWT), signed ES256
with a key generated and held on a hardware security key, with one section per machine. Each entry carries
its sequence number and the SHA-256 of the previous entry, so removing or changing an entry breaks the
chain. Signatures are low-S, so each entry has exactly one valid encoding.

- **Expiry:** three days after the oldest fetch it rests on. Evidence 24 hours old or older is not used.
- **Corrections:** a mistake is corrected by a new signed entry that names the one it corrects; the
  original stays in the feed.
- **Keys:** two P-256 keys, each generated on its own YubiKey, which needs its PIN and a touch for every
  signature. Either key may sign; an entry signed by one key may retire the other, never the last one.
- **Mirror:** every entry is appended to a NEAR testnet contract that checks the signature, that the key is
  one of the two and not retired, and the chain itself. The contract has no access keys left, so nobody can change its code. Readers compare
  two RPC providers at the same block.

## What passing the gate means

`watcher gate` passes a request only if the host's current verdict, after corrections, is unexpired and
`affirming` (or `warning`, if the caller asks for it). `watcher ask` then sends the request only over a
connection whose server key is one of the machines the verdict reviewed, checked during the TLS handshake,
before any request byte is sent. For a gateway route the only such key is the gateway machine's, since the
client never connects to a candidate, so a gateway route passes only with `warning` accepted.

Through the gateway, `watcher ask` also encrypts the prompt end to end, with NEAR's encryption (version 2:
X25519, HKDF-SHA256, XChaCha20-Poly1305), to the model key of a candidate in the verdict whose key is bound
to its quote (`signer_bound`) and which was reached directly; without such a candidate the gate refuses.
The gateway then relays ciphertext, and an answer that does not decrypt to the request's fresh key is
refused. This hides the prompt and the answer from the gateway machine. It does not hide which model is
asked, the sizes or the timing; it does not show which machine wrote the answer, since the gateway sees the
key the answer is encrypted to; and every machine of the model holds the same key, including machines the
verdict did not review.

## What a verdict does not say

- That the hardware resists physical or side-channel attacks. Attestation trusts the CPU and GPU vendors'
  keys and their patch ratings.
- That the containers' code is safe, or that the provider will not deploy different code tomorrow. A new
  release is a new review.
- Who can obtain the app's keys. The key service releases them to any code its authorisation contract
  admits, and those contracts are not checked.
- That the GPUs are attached to this machine beyond a shared nonce, or that machines not reached by our
  fetches are configured the same way.

## Independence

No reviewed provider pays for a review or a verdict. One possible exception is disclosed: this repository
is an entry in NEAR's hackathon, whose prizes NEAR pays, and NEAR is a provider the feed reviews. If the
entry wins a prize, its amount is fixed by the organisers' published rules and does not depend on any
verdict.

Before a provider's first verdict that shows a warning or a failure, the provider is told privately and
given 7 days. If users face a risk they can act on now, the verdict is published at once and the provider
is told at the same time.
