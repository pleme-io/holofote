# holofote

**A typed Splunk REST client and an observe-only MCP server.**

*holofote* is Brazilian Portuguese for *searchlight*: it points at a Splunk
host, or several, and reports what it sees. It never writes.

Two workspace members:

| crate | what it is |
|---|---|
| `holofote` | the library — a transport seam, a closed route enum, a typed SPL AST with exactly one renderer, a results route derived from the server version, shikumi config, and an outcome sum. No rmcp dependency. |
| `holofote-mcp` | the stdio MCP server (rmcp) — three tools over one target, or over several targets addressed by label. |

## The four outcomes

The reader of an MCP answer is a language model with no peripheral vision. It
cannot tell an empty index from a host behind a VPN it is not on — unless the
bytes say so. So every answer carries an `outcome` discriminant from
[kotae](https://github.com/pleme-io/kotae), and holofote never collapses two:

| outcome | `is_error` | what it means | when |
|---|---|---|---|
| `found` | false | here it is | the host answered with rows / indexes / identity |
| `empty` | false | **a finding**: there is nothing | a job finished DONE — and not finalized — with `resultCount: 0`; a role that sees no index |
| `refused` | true | the question was not accepted — `legal` names what would be | a bad time spec, a window that is provably backwards, `limit` out of `1..=maxResults`, a request over `maxTerms` / `maxTermBytes` / `maxFields`, an index or field outside the grammar, an unknown operator; a rejected credential (after one re-login); a Splunk `400 FATAL` (e.g. `Unknown search command`); a job Splunk marked failed |
| `blind` | true | the question could not be put — **conclude nothing** | a connect failure with plain TCP failing too (the message names the VPN, and says the probe agreed), a request timeout (names `requestTimeoutMs` — the host was reached), a TLS failure — a `rustls` error in the chain, or a connect-class failure while plain TCP opens (names `--tls`; see [TLS posture](#tls-posture)), a 5xx/429 (carries retry advice), a job Splunk finalized at `max_time` with no rows (a timeout, never `empty`), a job reaped before it was read (re-run), a 404 on a fixed route (not the management port), a missing credential file (names the path), no credential configured (names both legal forms) |

Every HTTP status is classified by [handan](https://github.com/pleme-io/handan)'s
`judge`; holofote never re-derives what a status means.

## The CLI contract

```
holofote-mcp --host <URL> --label <STRING>
             [--user-file <PATH> --password-file <PATH> | --token-file <PATH>]
             [--tls <system|accept-any|ca:<PEM_PATH>>] [--config <PATH>]

holofote-mcp --target <JSON> [--target <JSON> …] [--config <PATH>]
```

The first form serves one target, exactly as it always has. The second serves
every `--target` from one process; see [Several targets](#several-targets).

| flag | meaning |
|---|---|
| `--host <URL>` | required. Full URL with scheme and port: `https://splunk-a.example.com:8089`. Userinfo in the URL is refused; answers and logs render `scheme://host[:port]` only |
| `--label <STRING>` | required. Display label used in every answer, e.g. a tenant name (`alpha`) |
| `--user-file` + `--password-file` | session-key auth: `POST /services/auth/login` → `Authorization: Splunk <sessionKey>`. The two must appear together. |
| `--token-file <PATH>` | Bearer auth: `Authorization: Bearer <token>`. Conflicts with the pair. |
| `--tls` | TLS posture, default `system` — see below |
| `--config <PATH>` | optional shikumi YAML overlay for the bounds — see below |

With no credential flags the server still starts; every tool answers `blind`
naming the two legal forms. Credential files are read **when needed**, never at
startup: the token file on every call (a rotated token is picked up on the next
call); the user and password files at login and again after the host rejects
the cached session key (a rotated password is picked up on the next login).
Trailing newlines are trimmed and the contents are held only in
`zeroize::Zeroizing` memory — never in argv, the environment, logs, or answers;
the buffers handed to the HTTP stack are wiped when it releases them.
Logging goes to stderr only; stdout is the MCP transport.

## Several targets

Each `--target` is one JSON object carrying what the single-target flags carry,
under the same names:

```
--target '{"label":"alpha","host":"https://splunk-a.example.com:8089","tls":"accept-any","user-file":"/run/alpha/user","password-file":"/run/alpha/password"}'
--target '{"label":"beta","host":"https://splunk-b.example.com:8089","token-file":"/run/beta/token"}'
```

| key | meaning |
|---|---|
| `label` | required; the name a caller passes as `target`, and the label in every answer |
| `host` | required; as `--host` |
| `tls` | as `--tls`, default `system` |
| `user-file` + `password-file` / `token-file` | as the credential flags, with the same pairing rules |

Every target keeps its own host, TLS posture and credential; `--config` (the
bounds) is shared. An unknown key, a half credential pair, both credential
forms, a bad `tls` or a host that is not a URL is refused at parse; a label used
twice is refused at startup. `--target` conflicts with `--host`, `--label`,
`--tls` and the credential flags.

With `--target`, every tool takes a **required** `target` (the label), the
schema says so, and the server instructions name the legal targets once. An
unknown or missing `target` is `refused`, with `legal` listing every label
served. One target answering `blind` says nothing about another. In the
single-target form the schemas are what they always were — no `target` — and a
`target` a client sends anyway must be the one label.

## Tools

| tool | input | found payload |
|---|---|---|
| `splunk_whoami` | `{target}` with `--target`, else `{}` | `label, host, version, build, server_name, username, roles, tls_posture, results_route` — the cheap reachability + credential probe |
| `splunk_indexes` | `{target, limit?}` / `{limit?}` | `indexes: [{name, total_event_count?, min_time?, max_time?}], total, truncated` |
| `splunk_search` | `{target, index, terms?, earliest, latest?, limit, fields?, stats_count_by?, sort?}` | `spl, sid, result_count, fields, rows, truncated, finalized, messages?` |

`splunk_search` renders exactly one shape:

```
search index="<index>" <terms…> | stats count by f1 f2 | fields … | sort <limit+1> -f | head <limit+1>
```

The `+1` is the **probe row**: the client asks Splunk for one row more than the
caller wants, so `truncated` is a fact the wire carries — the extra row came
back, so more matched than `limit` — rather than a comparison of two
post-`head` counters that can never differ. The probe row is dropped before
answering; `rows` never exceeds `limit`. `truncated` is also true when
`finalized` is: Splunk stopped the search at `max_time` before it completed, and
the rows are what it had by then (`messages` carries Splunk's own note). A
finalized job with **no** rows is `blind`, not `empty`.

A term is `{field?, op?, value}`; `op` is one of `eq ne gt lt ge le` (default
`eq`), and a term with no field is a free-text phrase. Values are always quoted
by the renderer with `\` and `"` escaped, so `| delete` inside a value is a
harmless literal. `earliest` and `limit` are **required**: a REST search with no
bounds is an all-time search, and `count=0` means ALL to Splunk. Time specs are
`now`, Splunk relative time (`-15m`, `-24h@h`, `-7d@w0`, `@d`; units
`s m h d w mon q y`, snaps a unit or `w0..w6`), a 10-digit epoch, or RFC 3339.
A window that is provably backwards without a clock — two epochs, `now` against
`-1h`, `-1h` against `-2h`, `-90m` against `-1h` — is `refused`; one that cannot
be ordered without a clock (a snap, an epoch against a relative time, a day
against an hour) is passed through. Every dimension of a request is bounded by
the deployment: `limit` by `maxResults`, the term count by `maxTerms`, one term
value's length by `maxTermBytes`, each field list by `maxFields`; over a bound
is `refused` naming the key.

There is deliberately no tool that writes: the library's `Route` enum has no
mutating arm, so a write is a compile error, not a runtime refusal.

## The results route is derived from the server version

Splunk moved the results endpoint. `/services/search/v2/jobs/{sid}/results`
exists from 9.0 and is a **404** on 8.x; the v1 route
`/services/search/jobs/{sid}/results` is the only one on 8.x and is deprecated —
disabled by default — from 9.0.1. So holofote reads `GET /services/server/info`
once, parses `version`, and derives the route: `major.minor >= 9.0` → v2, else
v1. A version that does not parse is `blind`, never a guessed route.
`splunk_whoami` reports the derived `results_route`.

The job lifecycle is `create → poll → results → delete`. The `DELETE` runs on
every path out — success, empty, failure, and the holofote-side timeout — so a
job is never left holding dispatch quota.

## TLS posture

Splunk ships a stock self-signed certificate (`CN=SplunkServerDefaultCert`) that
no public root signs, so `system` verification fails against an untouched
install. That is typed as three postures rather than dissolved into a boolean:

| `--tls` | behaviour |
|---|---|
| `system` (default) | verify against the public web-PKI roots |
| `accept-any` | accept any certificate and hostname — **degraded**, logged once at startup and named in every `whoami` |
| `ca:<PEM_PATH>` | add one private root to the trusted set |

A TLS failure is `blind` naming the posture in force and the two remedies.

It is recognised two ways, because one is not enough. By **type**: a
`rustls::Error` anywhere in reqwest's error chain. And by **evidence**, for the
case measured 2026-09-09 (reqwest 0.12.28, rustls 0.23.44) against a host
presenting a self-signed certificate under `system`: the handshake ran past the
connect timeout, and the chain that came back was `client error (Connect)` →
`operation timed out` with **no `rustls::Error` in it** — byte-for-byte what a
filtered port produces, so by type alone a bad certificate read as a VPN that is
down (and, because `is_timeout()` was checked before `is_connect()`, a filtered
port could read as "the host is reachable, the call was slow" — the opposite of
the truth). So after any connect-class failure no rustls error explains, holofote
makes **one bounded plain-TCP connect** to the same host and port, on the same
connect budget, and the answer carries what it found (`ConnectEvidence`, a typed
field rendered once — never prose assembled at the failure site):

| plain TCP | under | classified as | the agent reads |
|---|---|---|---|
| opens | `system` / `ca:<PEM>` | TLS | `--tls` and the two remedies, plus "(a plain TCP connection to host:port opens within the connect timeout, so the failure is past TCP — in the TLS handshake or just after)" |
| opens | `accept-any` | a plain transport failure — a certificate cannot be the cause | the transport's words plus the same parenthetical; never the VPN message |
| fails too | any | connect | the VPN message plus "(a plain TCP connection to host:port also fails within the connect timeout)" |
| could not be probed | any | connect | the VPN message, unadorned |

Precedence is TLS by type, then connect-class (a connect timeout IS a connect
failure), then a request that outran `requestTimeoutMs`, then everything else.
The decision is a pure function (`transport::classify_with`) driven by a table
test with no `reqwest::Error` in it.

## Configuration tiers

`HolofoteConfig` is one struct with two faces: shikumi's `TieredConfig` and a
tatara-lisp `(defholofote …)` form (`holofote/specs/holofote.lisp`). Every field
is a **bound**; none is a host, a label, or a credential.

| key (YAML, camelCase) | prescribed | sent to Splunk as |
|---|---|---|
| `maxResults` | 1000 | the cap on `limit`; `limit + 1` (the probe row) goes out as `max_count` and the results `count` |
| `defaultIndexesLimit` | 100 | — |
| `pollIntervalMs` | 500 | — |
| `maxSearchSeconds` | 60 | `max_time` |
| `jobTtlSeconds` | 300 | `timeout` |
| `jobAutoCancelSeconds` | 120 | `auto_cancel` |
| `connectTimeoutMs` | 5000 | — |
| `requestTimeoutMs` | 30000 | — |
| `maxTerms` | 32 | — (a request over it is refused) |
| `maxTermBytes` | 4096 | — (per term value; refused) |
| `maxFields` | 32 | — (per `fields` / `stats_count_by` list; refused) |

`bare()` is the zero-opinion floor (`maxResults: 1`). `prescribed_default()` is
what the server boots with and is pinned to the authored `.lisp`. `--config`
folds a **partial** YAML overlay onto prescribed; an unknown key is refused by
name, and a zero bound that would make every request illegal is refused too.

## Development

```
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test && gen build .
```

All client logic is tested against a scripted `MockTransport` (feature `mock`;
on for the workspace's own tests, off in the shipped library) with zero network:
the login flow and header shape, exactly one re-login on 401, the version→route
table, SPL rendering and injection cases, the time-spec grammar and the
clockless window ordering, the result cap and the probe row, every search
bound, that a finalized job is never `empty`, that a request timeout and a
reaped job are not read as a VPN outage or a version bug, that
`empty`/`refused`/`blind` render to different bytes, that the job is deleted
after results and after a poll timeout, and that `count` is never 0.
`tests/no_estate_identifiers.rs` walks everything git ships — source, docs,
manifests, lock files, workflows, the licence — and keeps it free of estate
names (whole tokens and windows inside them) and of `format!` calls, or their
hand-expansions, outside test modules.

Built with Nix via `substrate.rust.workspace` (`flake.nix`); `Cargo.gen.lock` is
committed, `Cargo.build-spec.json` is ignored.

## License

MIT — pleme-io.
