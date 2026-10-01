# holofote — typed Splunk REST client + observe-only MCP server

<!-- Non-applicable ★★ directive waivers (holofote is a stdio binary that READS
     one Splunk host; it has no in-cluster runtime and never writes): -->
skip-urdume: binary-not-a-service
skip-tela: binary-not-web
skip-helm-native: pure-binary-no-cluster-runtime
skip-gitops: pure-binary-no-cluster-runtime
skip-magma: pure-binary-no-cluster-runtime
skip-continuous-convergence: pure-binary-no-cluster-runtime
skip-platform-mediated: pure-binary-no-cluster-runtime

One-sentence purpose: ask a Splunk host three observe-only questions — who am I,
which indexes can I see, run one bounded search — and answer each with one of
kotae's four outcomes, so a host behind a down VPN is never read as an empty index.
One process can serve several hosts (`--target`, repeated), each addressed by label.

## Public and generic — no estate identifiers

This repo is PUBLIC (MIT). It contains no company, tenant, host, environment
codename or person name; docs and tests use `example.com` hosts and the labels
`alpha` / `beta`. `holofote/tests/no_estate_identifiers.rs` walks everything git
ships — `.rs/.md/.toml/.nix/.lisp/.yml/.yaml/.json/.lock` and every
extension-less file (`LICENSE`, `.gitignore`), workflows and lock files included
— and BLAKE3-compares each token, and every 4–32-byte window inside it, against
a hashed denylist. Keep it that way: the deployment (hosts, labels, credential
paths) is argv, emitted by the Nix side — and a comment describes no estate
either (no host counts, no measured fleet versions).

## Where to look

| Concern | File |
|---|---|
| the seam — `Transport`, `ReqwestTransport`, `MockTransport` (feature `mock`); failure classification: `ErrorShape` + `ConnectEvidence` → the pure `classify_with` | `holofote/src/transport.rs` |
| the closed `Route` enum, its ONE `Display`, the validated `Sid`, what a 404 means per route (`Absence`) | `holofote/src/route.rs` |
| credentials read when needed into `Zeroizing`, header rendering | `holofote/src/auth.rs` |
| `ServerVersion` → `ResultsRoute` (`>= 9.0` → v2, else v1) | `holofote/src/version.rs` |
| typed SPL: `IndexName`/`FieldName` grammar, `TimeSpec` + clockless ordering, `ResultCap` + the probe row, `SearchBounds`, the ONE renderer | `holofote/src/spl.rs` |
| `Outcome` + the typed `Blindness` / `Refusal` causes | `holofote/src/outcome.rs` |
| `SplunkClient<T: Transport>`: login, the single re-login, the job lifecycle | `holofote/src/client.rs` |
| `Targets<T>`: several clients keyed by label; `resolve` → client or a `Refusal` naming every label | `holofote/src/targets.rs` |
| `HolofoteConfig`: shikumi tiers + `(defholofote …)` on one struct | `holofote/src/config.rs`, `holofote/specs/holofote.lisp` |
| the CLI contract, tool inputs, the MCP border | `holofote-mcp/src/main.rs` |

## Invariants, and where each is sealed

- **No write has a code path.** `Route` has no mutating arm, so a write is
  `E0599`, not a runtime refusal. Do not add one.
- **One SPL renderer.** `impl Display for Search` is the only place SPL text is
  assembled; there is no raw-SPL entry point. Values are always quoted (`\` and
  `"` escaped) — `hostile_values_render_as_harmless_quoted_literals` proves
  `| delete` inside a value stays a literal.
- **`earliest` and `limit` are required fields**, because a REST search with no
  bounds is an all-time search and `count=0` means ALL. `ResultCap` is `1..=cap`.
  A window that is provably backwards without a clock is `refused`, never sent.
- **Every request dimension is bounded** — `maxResults`, `maxTerms`,
  `maxTermBytes`, `maxFields` — and over a bound is `refused` naming the key,
  before anything is parsed or sent.
- **`truncated` is a fact the wire carries.** `sort`/`head` and the results
  `count` ask for `limit + 1` (the probe row); it came back ⇒ more matched than
  `limit`; it is dropped before answering. Never a comparison of two post-`head`
  counters — that can never be true.
- **The results route is derived from the server version**, read once from
  `/services/server/info`: v2 is a 404 on 8.x, v1 is disabled by default from
  9.0.1. Never configure it; never guess it — an unparseable version is `blind`.
- **Every HTTP status is judged by `handan::judge`.** Nothing here re-derives
  what a 403 means. 401/403 on the password path re-logins ONCE and retries ONCE.
- **Four outcomes, never collapsed.** connect (plain TCP fails too) → `blind`
  naming the VPN; request timeout → `blind` naming `requestTimeoutMs` (the host
  WAS reached); TLS → `blind` naming `--tls` — recognised by TYPE (a
  `rustls::Error` in the chain) OR by EVIDENCE (a connect-class failure while a
  bounded plain-TCP probe to the same host:port opens), because the handshake
  can outrun the connect timeout and leave no rustls error at all (measured
  2026-09-09; that chain is identical to a filtered port's). Precedence is
  TLS-by-type, then `is_connect()` (a connect timeout IS a connect failure),
  then `is_timeout()`. The decision is the pure `transport::classify_with`
  over `ErrorShape` + `ConnectEvidence` + posture, table-tested with no
  `reqwest::Error`; under `accept-any` TCP-opens is a plain transport failure
  carrying the evidence, never the VPN message; 5xx/429 → `blind` with retry advice; 404 → `blind` for
  what the ROUTE's absence means (`Route::absence`: results route → version
  pairing; job route → reaped, re-run; fixed route → not the management API);
  400 FATAL / validation failure / rejected credential → `refused` with the
  legal set; a DONE job with zero results → `empty` (a finding) — unless Splunk
  FINALIZED it at `max_time`, which is `blind` (a timeout), and with rows is
  `found` with `truncated` + `finalized` true. `is_error` on the MCP result is
  derived from the discriminant in exactly one function (`answer`).
- **Secrets never leave zeroizing memory.** Read when needed, not at startup:
  the token file per call, the user/password files at login and after a rejected
  session. The buffers handed to reqwest (header value, login body) are
  `Bytes::from_owner(Zeroizing<_>)`, wiped when hyper releases them; hyper's own
  wire copy is the honest limit. A `--host` with userinfo is refused by the
  transport without echoing it, and the host label is `scheme://host[:port]`.
  `Debug` impls redact; login bodies are never logged; tracing is stderr only.
  `MockTransport` / `RecordedCall` (plain-string copies, by design) compile only
  under `cfg(test)` or the `mock` feature.
- **Typed emission.** No `format!` macro call — nor `format_args!(` / `fmt::format(`
  — outside `#[cfg(test)] mod` blocks; the ban test walks both members and
  strips those blocks first. Use `write!` into a `Display`, thiserror, tracing,
  or serde.
- **A target is addressed by label, and a bad address is `refused`.** With
  `--target`, `Refusal::UnknownTarget` / `TargetRequired` carry every label as
  `legal`; the schema marks `target` required on all three tools, and the
  instructions name the labels once. The single-target form (`--host`/`--label`)
  is unchanged on the wire: its schemas carry no `target` (stripped at
  construction), and a `target` sent anyway must equal the one label.
- **The job is released on every path** — success, empty, failed, and timeout —
  by a best-effort `DELETE`; four tests pin it.

## Gates

`cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test && gen build .`
All client logic is mock-green with zero network. `Cargo.gen.lock` is committed;
`Cargo.build-spec.json` is ignored. The flake is four lines over
`substrate.rust.workspace`.
