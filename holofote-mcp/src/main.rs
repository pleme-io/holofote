//! holofote-mcp — the observe-only Splunk MCP server, on stdio.
//!
//! Three tools over one target or several (each its own host, TLS posture
//! and credential, addressed by label), and every answer is one of kotae's
//! four outcomes. This binary owns the **wire** and nothing else:
//! argv, the transport, the runtime, the MCP framing. Every decision about
//! what a Splunk answer *means* lives in the `holofote` library, where it is
//! tested against a scripted transport with no network at all.
//!
//! ## Why the answers look the way they do
//!
//! The reader is a language model with no peripheral vision. It cannot tell
//! an empty index from a host that is behind a VPN it is not on — unless the
//! bytes say so. So a search with no hits is `empty` (a finding), a bad time
//! spec is `refused` (the legal forms are listed), and an unreachable host is
//! `blind` (nobody knows — conclude nothing). `is_error` on the MCP result
//! is derived from that discriminant, never chosen by hand.
//!
//! ## What is deliberately absent
//!
//! There is no tool that writes. The library's route enum has no arm for a
//! write, so a mutating tool could not be built here even by accident.
//!
//! ## Where secrets go
//!
//! Credentials are file paths on argv; the files are read when needed —
//! the token file on every call, the user/password files at login and
//! after a rejected session — into zeroizing memory and never logged. A
//! `--host` URL carrying userinfo is refused at startup, and the host as
//! it appears in answers and logs is rendered from scheme, host and port
//! only. `tracing` goes to stderr only — stdout is the MCP transport, and
//! a log line on stdout would corrupt it.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use holofote::client::{IndexList, SearchHits, WhoAmI};
use holofote::outcome::{Failure, Refusal};
use holofote::tls::TlsPostureError;
use holofote::transport::{ReqwestTransport, Transport};
use holofote::{
    Credential, HolofoteConfig, Identity, Outcome, SearchRequest, SortRequest, SplunkClient,
    Targets, TargetsError, TermRequest, TlsPosture,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::Value;

/// The instructions every client receives — the four outcomes, and the one
/// reading an agent most often gets wrong.
const INSTRUCTIONS: &str = "holofote — an observe-only Splunk client. Three tools: `splunk_whoami` (the cheap \
reachability + credential probe: version, build, roles, TLS posture, which results route the \
server version selects), `splunk_indexes` (the indexes this credential can see), and \
`splunk_search` (one bounded search: an index, typed terms, a REQUIRED earliest bound, a \
REQUIRED result limit). There is no tool that writes; the client has no mutating method. \
Every answer carries an `outcome` discriminant and it is one of exactly four: `found` (here it \
is), `empty` (the host answered and there is nothing — a FINDING, e.g. no events visible to \
this role in that window), `refused` (the question was not accepted — a bad time spec, a limit \
out of bounds, an illegal index name, a rejected credential, or a Splunk FATAL — and `legal` \
names what would be accepted, so retry differently), and `blind` (the question could not be \
put at all — conclude NOTHING about the subject). `blind` usually means the VPN this host \
lives behind is not connected; it is also a TLS posture mismatch (`--tls`), a 5xx/429 with \
retry advice, or a missing credential file, and the message names which. Never read `blind` \
or `refused` as `empty`.";

const NAMED_TARGETS_PREAMBLE: &str = " This server serves several Splunk targets, each with its own host, TLS \
posture and credential. Every tool takes a REQUIRED `target`, one of: ";

const NAMED_TARGETS_CODA: &str = ". A missing or unknown `target` is `refused` naming these; one target \
answering `blind` says nothing about another.";

const TARGET_DESCRIPTION: &str =
    "Which configured Splunk target to ask: one of the labels the server instructions list.";

const TARGET_KEYS: [&str; 6] = [
    "label",
    "host",
    "tls",
    "user-file",
    "password-file",
    "token-file",
];

// ── argv ───────────────────────────────────────────────────────────────

/// The CLI contract. The Nix side emits exactly these flags.
#[derive(Debug, Parser)]
#[command(
    name = "holofote-mcp",
    version,
    about = "observe-only Splunk MCP server (stdio)"
)]
struct Cli {
    /// Full management-API URL including scheme and port, e.g.
    /// `https://splunk-a.example.com:8089`.
    #[arg(
        long,
        value_name = "URL",
        required_unless_present = "targets",
        conflicts_with = "targets"
    )]
    host: Option<url::Url>,

    /// Display label used in every answer — a tenant name, never a hostname.
    #[arg(
        long,
        value_name = "STRING",
        required_unless_present = "targets",
        conflicts_with = "targets"
    )]
    label: Option<String>,

    /// File holding the Splunk username (session-key auth). Requires
    /// `--password-file`; conflicts with `--token-file`.
    #[arg(
        long,
        value_name = "PATH",
        requires = "password_file",
        conflicts_with_all = ["token_file", "targets"]
    )]
    user_file: Option<PathBuf>,

    /// File holding the Splunk password (session-key auth). Requires
    /// `--user-file`; conflicts with `--token-file`.
    #[arg(
        long,
        value_name = "PATH",
        requires = "user_file",
        conflicts_with_all = ["token_file", "targets"]
    )]
    password_file: Option<PathBuf>,

    /// File holding a Splunk authentication token (Bearer auth).
    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    token_file: Option<PathBuf>,

    /// TLS posture: `system` (public roots), `accept-any` (degraded — Splunk's
    /// stock certificate is self-signed), or `ca:<PEM_PATH>` (a private root).
    #[arg(
        long,
        value_name = "system|accept-any|ca:<PEM_PATH>",
        default_value = "system",
        conflicts_with = "targets"
    )]
    tls: TlsPosture,

    #[arg(
        long = "target",
        value_name = "JSON",
        help = "One Splunk target as a JSON object with keys label, host, tls, user-file, password-file, token-file. Repeat it to serve several targets from one server; every tool then takes a required `target`. Conflicts with --host/--label/--tls and the credential flags"
    )]
    targets: Vec<Endpoint>,

    /// Optional shikumi YAML overlay for the bounds (`HolofoteConfig`); an
    /// unknown key is refused, a partial file folds onto the prescribed tier.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

/// Why the server could not start. Each arm is one argv-level fact.
#[derive(Debug, thiserror::Error)]
enum StartError {
    /// `--host` must be `http(s)://<host>[:port]`.
    #[error(
        "host {label} must be an http or https URL naming a host, e.g. https://splunk-a.example.com:8089"
    )]
    Host {
        /// What was passed, as [`HostLabel`] renders it — never the raw URL,
        /// which may carry userinfo.
        label: String,
    },
    /// The bounds overlay was refused.
    #[error(transparent)]
    Config(#[from] holofote::ConfigError),
    /// The HTTP client could not be built.
    #[error(transparent)]
    Transport(#[from] holofote::transport::TransportBuildError),
    #[error(transparent)]
    Targets(#[from] TargetsError),
}

impl Cli {
    /// The credential the flags describe. clap has already enforced that
    /// the password pair travels together and excludes the token.
    fn credential(&self) -> Credential {
        credential_from(
            self.user_file.clone(),
            self.password_file.clone(),
            self.token_file.clone(),
        )
        .unwrap_or(Credential::None)
    }

    fn addressing(&self) -> Addressing {
        if self.targets.is_empty() {
            Addressing::Implicit
        } else {
            Addressing::Named
        }
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        match (&self.host, &self.label) {
            (Some(host), Some(label)) => vec![Endpoint {
                label: label.clone(),
                host: host.clone(),
                tls: self.tls.clone(),
                credential: self.credential(),
            }],
            _ => self.targets.clone(),
        }
    }

    fn config(&self) -> Result<HolofoteConfig, StartError> {
        use shikumi::TieredConfig as _;
        Ok(match &self.config {
            Some(path) => HolofoteConfig::from_overlay_file(path)?,
            None => HolofoteConfig::prescribed_default(),
        })
    }

    fn server(&self) -> Result<HolofoteMcp, StartError> {
        let config = self.config()?;
        let clients = self
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.client(&config))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(HolofoteMcp::new(Targets::new(clients)?, self.addressing()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addressing {
    Implicit,
    Named,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    label: String,
    host: url::Url,
    tls: TlsPosture,
    credential: Credential,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct TargetArg {
    label: String,
    host: String,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    user_file: Option<PathBuf>,
    #[serde(default)]
    password_file: Option<PathBuf>,
    #[serde(default)]
    token_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum TargetArgError {
    #[error("--target must be one JSON object with keys {}: {source}", TARGET_KEYS.join(", "))]
    Json {
        #[source]
        source: serde_json::Error,
    },
    #[error("--target {label}: host is not a URL: {source}")]
    Url {
        label: String,
        #[source]
        source: url::ParseError,
    },
    #[error("--target {label}: {source}")]
    Tls {
        label: String,
        #[source]
        source: TlsPostureError,
    },
    #[error("--target {label}: {shape}")]
    Credential {
        label: String,
        shape: CredentialShapeError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum CredentialShapeError {
    #[error("user-file and password-file must appear together; session-key auth needs both")]
    HalfPair,
    #[error("token-file conflicts with user-file/password-file; pick one credential form")]
    BothForms,
}

fn credential_from(
    user_file: Option<PathBuf>,
    password_file: Option<PathBuf>,
    token_file: Option<PathBuf>,
) -> Result<Credential, CredentialShapeError> {
    match (user_file, password_file, token_file) {
        (Some(user_file), Some(password_file), None) => Ok(Credential::Password {
            user_file,
            password_file,
        }),
        (None, None, Some(token_file)) => Ok(Credential::Token { token_file }),
        (None, None, None) => Ok(Credential::None),
        (Some(_), None, None) | (None, Some(_), None) => Err(CredentialShapeError::HalfPair),
        (_, _, Some(_)) => Err(CredentialShapeError::BothForms),
    }
}

impl FromStr for Endpoint {
    type Err = TargetArgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arg: TargetArg =
            serde_json::from_str(s).map_err(|source| TargetArgError::Json { source })?;
        let host = url::Url::parse(&arg.host).map_err(|source| TargetArgError::Url {
            label: arg.label.clone(),
            source,
        })?;
        let tls = match &arg.tls {
            Some(posture) => posture.parse().map_err(|source| TargetArgError::Tls {
                label: arg.label.clone(),
                source,
            })?,
            None => TlsPosture::System,
        };
        let credential = credential_from(arg.user_file, arg.password_file, arg.token_file)
            .map_err(|shape| TargetArgError::Credential {
                label: arg.label.clone(),
                shape,
            })?;
        Ok(Self {
            label: arg.label,
            host,
            tls,
            credential,
        })
    }
}

impl Endpoint {
    /// The host as it appears in answers and logs — see [`HostLabel`].
    fn host_label(&self) -> String {
        HostLabel(&self.host).to_string()
    }

    fn validate_host(&self) -> Result<(), StartError> {
        let scheme_ok = matches!(self.host.scheme(), "http" | "https");
        if scheme_ok && self.host.host_str().is_some() {
            Ok(())
        } else {
            Err(StartError::Host {
                label: self.host_label(),
            })
        }
    }

    fn identity(&self) -> Identity {
        Identity {
            label: self.label.clone(),
            host: self.host_label(),
            tls_posture: self.tls.clone(),
        }
    }

    /// The production client: reqwest over rustls under the chosen posture.
    fn client(
        &self,
        config: &HolofoteConfig,
    ) -> Result<SplunkClient<Arc<dyn Transport>>, StartError> {
        self.validate_host()?;
        let transport = ReqwestTransport::new(self.host.clone(), &self.tls, config.timeouts())?;
        let transport: Arc<dyn Transport> = Arc::new(transport);
        Ok(SplunkClient::new(
            transport,
            self.credential.clone(),
            config.clone(),
            self.identity(),
        ))
    }

    fn announce(&self) {
        let host = self.host_label();
        if self.tls.is_degraded() {
            tracing::warn!(
                target_label = %self.label,
                host = %host,
                posture = %self.tls,
                "TLS posture is DEGRADED: certificates and hostnames are not verified for this host"
            );
        }
        match self.credential {
            Credential::None => {
                tracing::warn!(
                    target_label = %self.label,
                    host = %host,
                    "no credential configured; every tool will answer `blind` naming the two legal forms"
                );
            }
            Credential::Password { .. } => {
                tracing::info!(target_label = %self.label, host = %host, auth = "session-key", "starting");
            }
            Credential::Token { .. } => {
                tracing::info!(target_label = %self.label, host = %host, auth = "bearer", "starting");
            }
        }
    }
}

/// `scheme://host[:port]` — the one rendering of `--host` that reaches an
/// answer or a log line. Built from the URL's parts, never from its text,
/// so userinfo, a path, a query or a trailing slash cannot ride along.
struct HostLabel<'a>(&'a url::Url);

impl fmt::Display for HostLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}",
            self.0.scheme(),
            self.0.host_str().unwrap_or_default()
        )?;
        if let Some(port) = self.0.port() {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

// ── tool inputs ────────────────────────────────────────────────────────

/// `splunk_whoami` takes only the target: each target's host and credential
/// are fixed at startup.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WhoAmIInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
}

/// `splunk_indexes` — the indexes this credential can see.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct IndexesInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// How many indexes to list. Defaults to the configured
    /// `defaultIndexesLimit`; clamped into `1..=maxResults`.
    #[serde(default)]
    limit: Option<u32>,
}

/// One search term. With `field` it is a fielded comparison; without, a
/// free-text phrase. The value is always quoted by the renderer, so a `|`
/// or a quote inside it is a literal, never a pipeline stage.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TermInput {
    /// Field name (`[A-Za-z_][A-Za-z0-9_.:-]*`). Omit for a free-text phrase.
    #[serde(default)]
    field: Option<String>,
    /// One of `eq` `ne` `gt` `lt` `ge` `le`. Defaults to `eq`.
    #[serde(default)]
    op: Option<String>,
    /// The value to compare against.
    value: String,
}

/// A sort stage.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SortInput {
    /// Field to sort on.
    field: String,
    /// Sort descending when true; ascending otherwise.
    #[serde(default)]
    descending: bool,
}

/// `splunk_search` — one bounded search. Rendered as
/// `search index="<index>" <terms> | stats count by … | fields … | sort … | head <limit>`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SearchInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// The index to search (`[A-Za-z_][A-Za-z0-9_.:-]*`).
    index: String,
    /// Terms, all of which must match. Fielded (`field op value`) or
    /// free-text (`value` only).
    #[serde(default)]
    terms: Vec<TermInput>,
    /// REQUIRED lower time bound: `now`, a relative time (`-15m`, `-24h@h`,
    /// `-7d@w0`, `@d`), a 10-digit Unix epoch, or an RFC 3339 timestamp.
    /// Required because an unbounded REST search is an all-time search.
    earliest: String,
    /// Upper time bound, same forms. Defaults to `now`.
    #[serde(default)]
    latest: Option<String>,
    /// REQUIRED result cap, `1..=maxResults`. `0` is refused — Splunk reads
    /// it as ALL.
    limit: u32,
    /// `| fields …` — the fields to keep.
    #[serde(default)]
    fields: Vec<String>,
    /// `| stats count by …` — aggregate instead of listing events.
    #[serde(default)]
    stats_count_by: Vec<String>,
    /// `| sort …`.
    #[serde(default)]
    sort: Option<SortInput>,
}

impl From<TermInput> for TermRequest {
    fn from(t: TermInput) -> Self {
        Self {
            field: t.field,
            op: t.op,
            value: t.value,
        }
    }
}

impl From<SortInput> for SortRequest {
    fn from(s: SortInput) -> Self {
        Self {
            field: s.field,
            descending: s.descending,
        }
    }
}

impl From<SearchInput> for SearchRequest {
    fn from(s: SearchInput) -> Self {
        Self {
            index: s.index,
            terms: s.terms.into_iter().map(Into::into).collect(),
            earliest: s.earliest,
            latest: s.latest,
            limit: s.limit,
            fields: s.fields,
            stats_count_by: s.stats_count_by,
            sort: s.sort.map(Into::into),
        }
    }
}

// ── the server ─────────────────────────────────────────────────────────

/// The MCP face over one [`SplunkClient`]. Generic over nothing: the
/// transport is `dyn`, so a test builds the SAME type over a scripted mock.
#[derive(Clone)]
struct HolofoteMcp {
    targets: Arc<Targets<Arc<dyn Transport>>>,
    tool_router: ToolRouter<Self>,
    instructions: Arc<str>,
}

/// The one place an [`Outcome`] becomes an MCP result. `is_error` is derived
/// from the discriminant: `found` and `empty` are answers about the world;
/// `refused` and `blind` are about the attempt, and a client that treats
/// those as errors is reading them correctly.
fn answer<P: serde::Serialize>(outcome: Outcome<P>) -> CallToolResult {
    let a: kotae::Answer = outcome.into();
    let content = vec![Content::text(a.render())];
    if a.is_about_the_world() {
        CallToolResult::success(content)
    } else {
        CallToolResult::error(content)
    }
}

fn refused(refusal: Refusal) -> CallToolResult {
    answer::<()>(Failure::from(refusal).into())
}

fn shape_target(router: &mut ToolRouter<HolofoteMcp>, addressing: Addressing) {
    for route in router.map.values_mut() {
        let schema = Arc::make_mut(&mut route.attr.input_schema);
        match addressing {
            Addressing::Named => {
                let required = schema
                    .entry("required")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(names) = required
                    && !names.iter().any(|n| n == "target")
                {
                    names.push(Value::from("target"));
                }
            }
            Addressing::Implicit => {
                if let Some(Value::Object(properties)) = schema.get_mut("properties") {
                    properties.remove("target");
                    if properties.is_empty() {
                        schema.remove("properties");
                    }
                }
            }
        }
    }
}

fn instructions_for(targets: &Targets<Arc<dyn Transport>>, addressing: Addressing) -> String {
    let mut text = INSTRUCTIONS.to_owned();
    if addressing == Addressing::Named {
        text.push_str(NAMED_TARGETS_PREAMBLE);
        text.push_str(&targets.labels().collect::<Vec<_>>().join(", "));
        text.push_str(NAMED_TARGETS_CODA);
    }
    text
}

impl HolofoteMcp {
    fn new(targets: Targets<Arc<dyn Transport>>, addressing: Addressing) -> Self {
        let mut tool_router = Self::tool_router();
        shape_target(&mut tool_router, addressing);
        let instructions = instructions_for(&targets, addressing).into();
        Self {
            targets: Arc::new(targets),
            tool_router,
            instructions,
        }
    }

    fn pick(
        &self,
        target: Option<&str>,
    ) -> Result<&SplunkClient<Arc<dyn Transport>>, CallToolResult> {
        self.targets.resolve(target).map_err(refused)
    }
}

#[tool_router]
impl HolofoteMcp {
    /// The cheap probe: can the host be reached, does the credential work,
    /// which Splunk is it.
    #[tool(
        description = "Reachability + credential probe for the configured Splunk host: label, host, version, build, server name, the credential's username and roles, the TLS posture in force, and the results route (v1/v2) derived from the server version. `blind` here usually means the VPN is down."
    )]
    async fn splunk_whoami(&self, Parameters(input): Parameters<WhoAmIInput>) -> CallToolResult {
        match self.pick(input.target.as_deref()) {
            Ok(client) => answer::<WhoAmI>(client.whoami().await),
            Err(refusal) => refusal,
        }
    }

    /// The indexes this credential can see, with event counts and time
    /// bounds where Splunk reports them.
    #[tool(
        description = "List the indexes this credential can see, with totalEventCount / minTime / maxTime where reported. `empty` means the host answered and this role sees no index at all. `limit` defaults to the configured defaultIndexesLimit and is clamped into 1..=maxResults."
    )]
    async fn splunk_indexes(&self, Parameters(input): Parameters<IndexesInput>) -> CallToolResult {
        match self.pick(input.target.as_deref()) {
            Ok(client) => answer::<IndexList>(client.indexes(input.limit).await),
            Err(refusal) => refusal,
        }
    }

    /// One bounded search, validated before it touches the host.
    #[tool(
        description = "Run one bounded search: `search index=\"<index>\" <terms> | stats count by … | fields … | sort … | head <limit>`. `earliest` and `limit` are REQUIRED (an unbounded REST search is an all-time search; limit 0 means ALL to Splunk). `empty` means the job completed with zero results — a finding, not an error. `refused` carries the legal forms for whatever was rejected (time spec, limit bounds, identifier grammar, or Splunk's own FATAL message). The job is created, polled, read by the version-derived results route, and deleted."
    )]
    async fn splunk_search(&self, Parameters(input): Parameters<SearchInput>) -> CallToolResult {
        match self.pick(input.target.as_deref()) {
            Ok(client) => answer::<SearchHits>(client.search(input.into()).await),
            Err(refusal) => refusal,
        }
    }
}

// `router = self.tool_router`: the macro's default rebuilds the router on
// every call; naming the field reads the one built at construction. The
// allow covers the macro's generated `list_tools`, which is `async` by the
// trait's shape and has nothing to await.
#[allow(clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for HolofoteMcp {
    fn get_info(&self) -> ServerInfo {
        // rmcp 1.x marks ServerInfo #[non_exhaustive]; default-then-mutate is
        // the sanctioned construction.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(self.instructions.to_string());
        info
    }
}

// ── main ───────────────────────────────────────────────────────────────

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // stderr ONLY: stdout is the MCP transport.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

/// Why serving stopped before a clean close. Three phases, three arms.
#[derive(Debug, thiserror::Error)]
enum ServeError {
    /// The Tokio runtime could not be built.
    #[error("runtime could not be built: {0}")]
    Runtime(#[from] std::io::Error),
    /// The MCP initialize handshake on stdio failed. Boxed: the rmcp error
    /// carries the offending message and is ~500 bytes.
    #[error("MCP initialize handshake failed: {0}")]
    Initialize(#[from] Box<rmcp::service::ServerInitializeError>),
    /// The serving task ended abnormally.
    #[error("serving task ended abnormally: {0}")]
    Task(#[from] tokio::task::JoinError),
}

fn serve(server: HolofoteMcp) -> Result<(), ServeError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        use rmcp::ServiceExt as _;
        let service = server
            .serve(rmcp::transport::stdio())
            .await
            .map_err(Box::new)?;
        let reason = service.waiting().await?;
        tracing::info!(reason = ?reason, "holofote-mcp closed");
        Ok(())
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();
    let server = match cli.server() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "holofote-mcp could not start");
            return ExitCode::from(2);
        }
    };
    for endpoint in cli.endpoints() {
        endpoint.announce();
    }
    match serve(server) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "holofote-mcp stopped");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use holofote::route::Route;
    use holofote::transport::MockTransport;
    use serde_json::{Value, json};
    use shikumi::TieredConfig as _;
    use std::io::Write as _;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("holofote-mcp").chain(args.iter().copied()))
    }

    const BASE: [&str; 4] = [
        "--host",
        "https://splunk-a.example.com:8089",
        "--label",
        "alpha",
    ];

    fn sole(cli: &Cli) -> Endpoint {
        let mut endpoints = cli.endpoints();
        assert_eq!(
            endpoints.len(),
            1,
            "single-target flags describe one endpoint"
        );
        endpoints.remove(0)
    }

    fn with(extra: &[&str]) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = BASE.to_vec();
        for e in extra {
            v.push(Box::leak((*e).to_owned().into_boxed_str()));
        }
        v
    }

    #[test]
    fn the_cli_contract_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn host_and_label_are_required_and_credentials_default_to_none() {
        assert!(parse(&["--label", "alpha"]).is_err(), "--host is required");
        assert!(
            parse(&["--host", "https://h.example.com:8089"]).is_err(),
            "--label is required"
        );
        let cli = parse(&BASE).expect("parses");
        assert_eq!(cli.credential(), Credential::None);
        assert_eq!(cli.tls, TlsPosture::System, "system is the default posture");
        assert_eq!(
            sole(&cli).host_label(),
            "https://splunk-a.example.com:8089",
            "no trailing slash"
        );
        assert!(cli.config.is_none());
    }

    #[test]
    fn the_password_pair_travels_together_and_excludes_the_token() {
        assert!(
            parse(&with(&["--user-file", "/u"])).is_err(),
            "user without password"
        );
        assert!(
            parse(&with(&["--password-file", "/p"])).is_err(),
            "password without user"
        );
        assert!(
            parse(&with(&[
                "--user-file",
                "/u",
                "--password-file",
                "/p",
                "--token-file",
                "/t"
            ]))
            .is_err(),
            "token conflicts with the pair"
        );
        assert!(parse(&with(&["--user-file", "/u", "--token-file", "/t"])).is_err());
        let pw = parse(&with(&["--user-file", "/u", "--password-file", "/p"])).expect("pair");
        assert_eq!(
            pw.credential(),
            Credential::Password {
                user_file: "/u".into(),
                password_file: "/p".into()
            }
        );
        let tok = parse(&with(&["--token-file", "/t"])).expect("token");
        assert_eq!(
            tok.credential(),
            Credential::Token {
                token_file: "/t".into()
            }
        );
    }

    #[test]
    fn the_tls_flag_is_the_typed_posture_and_names_its_legal_set() {
        assert_eq!(
            parse(&with(&["--tls", "accept-any"])).expect("ok").tls,
            TlsPosture::AcceptAny
        );
        assert_eq!(
            parse(&with(&["--tls", "ca:/etc/ssl/private-root.pem"]))
                .expect("ok")
                .tls,
            TlsPosture::Ca("/etc/ssl/private-root.pem".into())
        );
        let err = parse(&with(&["--tls", "insecure"])).expect_err("refused");
        let msg = err.to_string();
        assert!(
            msg.contains("accept-any") && msg.contains("ca:<PEM_PATH>"),
            "{msg}"
        );
    }

    #[test]
    fn a_host_without_scheme_or_name_is_refused_at_startup() {
        let cli =
            parse(&["--host", "mailto:ops@example.com", "--label", "alpha"]).expect("url parses");
        assert!(matches!(
            sole(&cli).validate_host(),
            Err(StartError::Host { .. })
        ));
        assert!(sole(&parse(&BASE).expect("ok")).validate_host().is_ok());
        let http = parse(&[
            "--host",
            "http://splunk-b.example.com:8089",
            "--label",
            "beta",
        ])
        .expect("ok");
        assert!(sole(&http).validate_host().is_ok());
    }

    /// Userinfo in `--host` is refused at startup, and no rendering of the
    /// host — the label, the start error, the transport error — carries it.
    #[test]
    fn a_host_carrying_a_credential_is_refused_and_never_echoed() {
        let cli = parse(&[
            "--host",
            "https://observer:hunter2@splunk-a.example.com:8089/",
            "--label",
            "alpha",
        ])
        .expect("url parses");
        assert_eq!(
            sole(&cli).host_label(),
            "https://splunk-a.example.com:8089",
            "scheme, host and port only"
        );
        let err = cli.server().err().expect("refused");
        assert!(matches!(err, StartError::Transport(_)), "{err:?}");
        let msg = err.to_string();
        assert!(
            !msg.contains("hunter2") && !msg.contains("observer"),
            "{msg}"
        );
        for form in holofote::LEGAL_CREDENTIAL_FORMS {
            assert!(msg.contains(form), "{msg}");
        }

        // A bad scheme AND userinfo: the scheme error renders the label, not the URL.
        let cli = parse(&[
            "--host",
            "ftp://observer:hunter2@splunk-a.example.com:2121",
            "--label",
            "alpha",
        ])
        .expect("url parses");
        let msg = sole(&cli).validate_host().expect_err("refused").to_string();
        assert!(msg.contains("ftp://splunk-a.example.com:2121"), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");

        // No explicit port, a path and a trailing slash: none reach the label.
        let cli = parse(&[
            "--host",
            "https://splunk-b.example.com/x/",
            "--label",
            "beta",
        ])
        .expect("url parses");
        assert_eq!(sole(&cli).host_label(), "https://splunk-b.example.com");
    }

    #[test]
    fn a_config_overlay_folds_and_an_unknown_key_refuses_startup() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"maxResults: 25\n").expect("write");
        let path = f.path().to_str().expect("utf8 path").to_owned();
        let cli = parse(&with(&["--config", &path])).expect("ok");
        let cfg = cli.config().expect("loads");
        assert_eq!(cfg.max_results, 25);
        assert_eq!(
            cfg.poll_interval_ms,
            HolofoteConfig::prescribed_default().poll_interval_ms
        );

        let mut bad = tempfile::NamedTempFile::new().expect("tempfile");
        bad.write_all(b"maxResultz: 25\n").expect("write");
        let path = bad.path().to_str().expect("utf8 path").to_owned();
        let cli = parse(&with(&["--config", &path])).expect("ok");
        let err = cli.server().err().expect("refused");
        assert!(matches!(err, StartError::Config(_)), "{err:?}");
        assert!(err.to_string().contains("maxResultz"), "{err}");
    }

    #[test]
    fn the_production_client_builds_under_every_posture_without_touching_the_network() {
        for posture in ["system", "accept-any"] {
            let cli = parse(&with(&["--tls", posture])).expect("ok");
            cli.server().expect("builds");
        }
        let cli = parse(&with(&["--tls", "ca:/nope/holofote-root.pem"])).expect("ok");
        assert!(matches!(cli.server().err(), Some(StartError::Transport(_))));
    }

    // ── the MCP border, over a scripted transport ─────────────────────

    fn mock_client(
        label: &str,
        host: &str,
        mock: MockTransport,
        credential: Credential,
    ) -> SplunkClient<Arc<dyn Transport>> {
        let transport: Arc<dyn Transport> = Arc::new(mock);
        SplunkClient::new(
            transport,
            credential,
            HolofoteConfig::prescribed_default(),
            Identity {
                label: label.into(),
                host: host.into(),
                tls_posture: TlsPosture::AcceptAny,
            },
        )
    }

    fn server(mock: MockTransport, credential: Credential) -> HolofoteMcp {
        let client = mock_client(
            "alpha",
            "https://splunk-a.example.com:8089",
            mock,
            credential,
        );
        HolofoteMcp::new(
            Targets::new([client]).expect("one target"),
            Addressing::Implicit,
        )
    }

    fn token_file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f
    }

    fn text_of(result: &CallToolResult) -> Value {
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .expect("one text content")
            .text
            .clone();
        serde_json::from_str(&text).expect("the answer is JSON")
    }

    #[test]
    fn the_server_advertises_exactly_the_three_observe_tools() {
        let router = HolofoteMcp::tool_router();
        let mut names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["splunk_indexes", "splunk_search", "splunk_whoami"]);
        let search = router.get("splunk_search").expect("registered");
        let schema = serde_json::to_value(&search.input_schema).expect("schema");
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for must in ["index", "earliest", "limit"] {
            assert!(
                required.contains(&must),
                "{must} must be required: {schema}"
            );
        }
        assert!(!required.contains(&"latest"), "latest defaults to now");
    }

    #[test]
    fn the_instructions_teach_the_four_outcomes_and_the_vpn_reading() {
        let info = server(MockTransport::new(), Credential::None).get_info();
        assert!(
            info.capabilities.tools.is_some(),
            "tools must be advertised"
        );
        let instr = info.instructions.expect("instructions");
        for word in ["found", "empty", "refused", "blind", "VPN", "legal"] {
            assert!(instr.contains(word), "instructions must mention {word}");
        }
    }

    #[tokio::test]
    async fn no_credential_answers_blind_with_is_error_and_both_legal_forms() {
        let s = server(MockTransport::new(), Credential::None);
        let result = s
            .splunk_whoami(Parameters(WhoAmIInput { target: None }))
            .await;
        assert_eq!(result.is_error, Some(true));
        let v = text_of(&result);
        assert_eq!(v["outcome"], "blind");
        for form in holofote::LEGAL_CREDENTIAL_FORMS {
            assert!(v["because"].as_str().expect("because").contains(form));
        }
    }

    #[tokio::test]
    async fn whoami_over_a_scripted_host_is_found_and_not_an_error() {
        let tok = token_file("t0k\n");
        let mock = MockTransport::new()
            .reply_json(
                &Route::ServerInfo,
                vec![(
                    200,
                    json!({ "entry": [{ "name": "server-info", "content": { "version": "8.2.2.1", "build": "ae6821b7c64b", "serverName": "idx-a.example.com" } }] }),
                )],
            )
            .reply_json(
                &Route::CurrentContext,
                vec![(200, json!({ "entry": [{ "name": "context", "content": { "username": "observer", "roles": ["user"] } }] }))],
            );
        let s = server(
            mock,
            Credential::Token {
                token_file: tok.path().to_path_buf(),
            },
        );
        let result = s
            .splunk_whoami(Parameters(WhoAmIInput { target: None }))
            .await;
        assert_eq!(result.is_error, Some(false));
        let v = text_of(&result);
        assert_eq!(v["outcome"], "found");
        assert_eq!(v["label"], "alpha");
        assert_eq!(v["version"], "8.2.2.1");
        assert_eq!(v["results_route"], "v1");
        assert_eq!(v["tls_posture"], "accept-any");
        assert_eq!(v["username"], "observer");
    }

    #[tokio::test]
    async fn an_invalid_search_is_refused_with_is_error_and_a_legal_set() {
        let tok = token_file("t0k");
        let s = server(
            MockTransport::new(),
            Credential::Token {
                token_file: tok.path().to_path_buf(),
            },
        );
        let input: SearchInput = serde_json::from_value(json!({
            "index": "main", "earliest": "soon", "limit": 10
        }))
        .expect("deserializes");
        let result = s.splunk_search(Parameters(input)).await;
        assert_eq!(result.is_error, Some(true));
        let v = text_of(&result);
        assert_eq!(v["outcome"], "refused");
        assert_eq!(
            v["legal"].as_array().expect("legal").len(),
            holofote::spl::TimeSpec::LEGAL_FORMS.len()
        );
    }

    #[tokio::test]
    async fn an_empty_index_list_is_empty_and_not_an_error() {
        let tok = token_file("t0k");
        let mock = MockTransport::new().reply_json(
            &Route::Indexes,
            vec![(200, json!({ "entry": [], "paging": { "total": 0 } }))],
        );
        let s = server(
            mock,
            Credential::Token {
                token_file: tok.path().to_path_buf(),
            },
        );
        let result = s
            .splunk_indexes(Parameters(IndexesInput {
                target: None,
                limit: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(false), "empty is a finding");
        assert_eq!(text_of(&result)["outcome"], "empty");
    }

    #[test]
    fn search_input_maps_onto_the_library_request_field_for_field() {
        let input: SearchInput = serde_json::from_value(json!({
            "index": "main",
            "terms": [{ "field": "status", "op": "ge", "value": "500" }, { "value": "timeout" }],
            "earliest": "-15m",
            "limit": 5,
            "stats_count_by": ["host"],
            "sort": { "field": "count", "descending": true }
        }))
        .expect("deserializes");
        let req: SearchRequest = input.into();
        assert_eq!(req.index, "main");
        assert_eq!(req.terms.len(), 2);
        assert_eq!(req.terms[0].op.as_deref(), Some("ge"));
        assert_eq!(req.terms[1].field, None);
        assert_eq!(req.latest, None);
        assert_eq!(req.limit, 5);
        assert_eq!(req.stats_count_by, vec!["host".to_owned()]);
        assert_eq!(req.sort.as_ref().map(|s| s.descending), Some(true));
    }

    fn target_json(label: &str, host: &str, extra: &str) -> String {
        format!(r#"{{"label":"{label}","host":"{host}"{extra}}}"#)
    }

    fn two_targets() -> Vec<String> {
        vec![
            "--target".into(),
            target_json(
                "alpha",
                "https://splunk-a.example.com:8089",
                r#","tls":"accept-any","user-file":"/a/user","password-file":"/a/password""#,
            ),
            "--target".into(),
            target_json(
                "beta",
                "https://splunk-b.example.com:8089",
                r#","tls":"system","token-file":"/b/token""#,
            ),
        ]
    }

    fn parse_owned(args: &[String]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("holofote-mcp".to_owned()).chain(args.iter().cloned()))
    }

    #[test]
    fn each_target_keeps_its_own_host_tls_and_credential() {
        let cli = parse_owned(&two_targets()).expect("parses");
        assert_eq!(cli.addressing(), Addressing::Named);
        let endpoints = cli.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].label, "alpha");
        assert_eq!(
            endpoints[0].host_label(),
            "https://splunk-a.example.com:8089"
        );
        assert_eq!(endpoints[0].tls, TlsPosture::AcceptAny);
        assert_eq!(
            endpoints[0].credential,
            Credential::Password {
                user_file: "/a/user".into(),
                password_file: "/a/password".into()
            }
        );
        assert_eq!(endpoints[1].label, "beta");
        assert_eq!(
            endpoints[1].host_label(),
            "https://splunk-b.example.com:8089"
        );
        assert_eq!(endpoints[1].tls, TlsPosture::System);
        assert_eq!(
            endpoints[1].credential,
            Credential::Token {
                token_file: "/b/token".into()
            }
        );
        let bare = parse_owned(&[
            "--target".into(),
            target_json("gamma", "https://splunk.example.com:8089", ""),
        ])
        .expect("parses");
        assert_eq!(
            bare.endpoints()[0].tls,
            TlsPosture::System,
            "system is the default posture"
        );
        assert_eq!(bare.endpoints()[0].credential, Credential::None);
        let pinned = parse_owned(&[
            "--target".into(),
            target_json(
                "delta",
                "https://splunk.example.com:8089",
                r#","tls":"ca:/etc/ssl/private-root.pem""#,
            ),
        ])
        .expect("parses");
        assert_eq!(
            pinned.endpoints()[0].tls,
            TlsPosture::Ca("/etc/ssl/private-root.pem".into())
        );
    }

    #[test]
    fn single_target_flags_describe_one_implicit_endpoint() {
        let cli = parse(&with(&[
            "--user-file",
            "/u",
            "--password-file",
            "/p",
            "--tls",
            "accept-any",
        ]))
        .expect("parses");
        assert_eq!(cli.addressing(), Addressing::Implicit);
        let e = sole(&cli);
        assert_eq!(e.label, "alpha");
        assert_eq!(e.tls, TlsPosture::AcceptAny);
        assert_eq!(e.credential, cli.credential());
    }

    #[test]
    fn target_and_the_single_target_flags_are_exclusive() {
        let mut args: Vec<String> = BASE.iter().map(|s| (*s).to_owned()).collect();
        args.extend(two_targets());
        assert!(parse_owned(&args).is_err(), "--host/--label with --target");
        for flag in [["--tls", "accept-any"], ["--token-file", "/t"]] {
            let mut args = two_targets();
            args.extend(flag.iter().map(|s| (*s).to_owned()));
            assert!(parse_owned(&args).is_err(), "{flag:?} with --target");
        }
        let mut args = two_targets();
        args.extend(["--user-file", "/u", "--password-file", "/p"].map(str::to_owned));
        assert!(parse_owned(&args).is_err(), "credential pair with --target");
        assert!(parse(&[]).is_err(), "neither --host nor --target");
        let mut args = two_targets();
        args.extend(["--config", "/etc/holofote/bounds.yaml"].map(str::to_owned));
        assert!(
            parse_owned(&args).is_ok(),
            "the bounds overlay is shared by every target"
        );
    }

    #[test]
    fn a_malformed_target_is_refused_at_parse_naming_the_fault() {
        let cases: [(String, &str); 6] = [
            (
                "not json".into(),
                "label, host, tls, user-file, password-file, token-file",
            ),
            (
                target_json(
                    "alpha",
                    "https://h.example.com:8089",
                    r#","pasword-file":"/p""#,
                ),
                "pasword-file",
            ),
            (target_json("alpha", "not a url", ""), "host is not a URL"),
            (
                target_json(
                    "alpha",
                    "https://h.example.com:8089",
                    r#","tls":"insecure""#,
                ),
                "accept-any",
            ),
            (
                target_json(
                    "alpha",
                    "https://h.example.com:8089",
                    r#","user-file":"/u""#,
                ),
                "together",
            ),
            (
                target_json(
                    "alpha",
                    "https://h.example.com:8089",
                    r#","user-file":"/u","password-file":"/p","token-file":"/t""#,
                ),
                "pick one credential form",
            ),
        ];
        for (json, needle) in cases {
            let err = parse_owned(&["--target".into(), json.clone()]).expect_err(&json);
            let msg = err.to_string();
            assert!(msg.contains(needle), "{json}: {msg}");
        }
    }

    #[test]
    fn a_duplicate_target_label_refuses_startup() {
        let cli = parse_owned(&[
            "--target".into(),
            target_json("alpha", "https://splunk-a.example.com:8089", ""),
            "--target".into(),
            target_json("alpha", "https://splunk-b.example.com:8089", ""),
        ])
        .expect("parses");
        let err = cli.server().err().expect("refused");
        assert!(
            matches!(err, StartError::Targets(TargetsError::Duplicate { .. })),
            "{err:?}"
        );
        assert!(err.to_string().contains("alpha"), "{err}");
    }

    fn required_of(tool: &rmcp::model::Tool) -> Vec<String> {
        tool.input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_multi_target_server_requires_target_on_every_tool_and_names_the_targets_once() {
        let server = parse_owned(&two_targets())
            .expect("parses")
            .server()
            .expect("builds");
        let tools = server.tool_router.list_all();
        assert_eq!(tools.len(), 3, "still exactly three tools");
        for tool in &tools {
            assert!(
                required_of(tool).contains(&"target".to_owned()),
                "{} must require target",
                tool.name
            );
            assert!(tool.input_schema["properties"].get("target").is_some());
        }
        let search = tools
            .iter()
            .find(|t| t.name == "splunk_search")
            .expect("search");
        for must in ["index", "earliest", "limit", "target"] {
            assert!(required_of(search).contains(&must.to_owned()), "{must}");
        }
        let instr = server.get_info().instructions.expect("instructions");
        assert!(
            instr.starts_with(INSTRUCTIONS),
            "the single-target text is kept whole"
        );
        for label in ["alpha", "beta"] {
            assert_eq!(
                instr.matches(label).count(),
                1,
                "{label} named exactly once: {instr}"
            );
        }
        assert!(instr.contains("REQUIRED `target`"), "{instr}");
    }

    #[test]
    fn a_single_target_server_advertises_no_target_and_keeps_its_instructions() {
        let s = server(MockTransport::new(), Credential::None);
        for tool in s.tool_router.list_all() {
            assert!(
                tool.input_schema
                    .get("properties")
                    .and_then(|p| p.get("target"))
                    .is_none(),
                "{} advertises no target when it serves one",
                tool.name
            );
            assert!(
                !required_of(&tool).contains(&"target".to_owned()),
                "{}",
                tool.name
            );
        }
        assert_eq!(s.get_info().instructions.as_deref(), Some(INSTRUCTIONS));
    }

    fn fleet(
        alpha: MockTransport,
        beta: MockTransport,
        tok: &tempfile::NamedTempFile,
    ) -> HolofoteMcp {
        let credential = || Credential::Token {
            token_file: tok.path().to_path_buf(),
        };
        HolofoteMcp::new(
            Targets::new([
                mock_client(
                    "alpha",
                    "https://splunk-a.example.com:8089",
                    alpha,
                    credential(),
                ),
                mock_client(
                    "beta",
                    "https://splunk-b.example.com:8089",
                    beta,
                    credential(),
                ),
            ])
            .expect("two targets"),
            Addressing::Named,
        )
    }

    fn scripted_whoami(version: &str, server_name: &str) -> MockTransport {
        MockTransport::new()
            .reply_json(
                &Route::ServerInfo,
                vec![(
                    200,
                    json!({ "entry": [{ "name": "server-info", "content": { "version": version, "build": "b", "serverName": server_name } }] }),
                )],
            )
            .reply_json(
                &Route::CurrentContext,
                vec![(200, json!({ "entry": [{ "name": "context", "content": { "username": "observer", "roles": ["user"] } }] }))],
            )
    }

    #[tokio::test]
    async fn a_named_target_is_answered_by_its_own_host() {
        let tok = token_file("t0k");
        let s = fleet(
            scripted_whoami("8.2.2.1", "idx-a.example.com"),
            scripted_whoami("9.1.0", "idx-b.example.com"),
            &tok,
        );
        let a = text_of(
            &s.splunk_whoami(Parameters(WhoAmIInput {
                target: Some("alpha".into()),
            }))
            .await,
        );
        let b = text_of(
            &s.splunk_whoami(Parameters(WhoAmIInput {
                target: Some("beta".into()),
            }))
            .await,
        );
        assert_eq!(
            (a["outcome"].as_str(), a["label"].as_str()),
            (Some("found"), Some("alpha"))
        );
        assert_eq!(a["results_route"], "v1");
        assert_eq!(
            (b["outcome"].as_str(), b["label"].as_str()),
            (Some("found"), Some("beta"))
        );
        assert_eq!(b["results_route"], "v2");
    }

    #[tokio::test]
    async fn an_unknown_target_is_refused_naming_the_legal_targets() {
        let tok = token_file("t0k");
        let s = fleet(MockTransport::new(), MockTransport::new(), &tok);
        let result = s
            .splunk_indexes(Parameters(IndexesInput {
                target: Some("gamma".into()),
                limit: None,
            }))
            .await;
        assert_eq!(result.is_error, Some(true));
        let v = text_of(&result);
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["legal"], json!(["alpha", "beta"]));
        assert!(v["because"].as_str().expect("because").contains("gamma"));
    }

    #[tokio::test]
    async fn a_missing_target_on_a_multi_target_server_is_refused_naming_the_targets() {
        let tok = token_file("t0k");
        let s = fleet(MockTransport::new(), MockTransport::new(), &tok);
        let input: SearchInput = serde_json::from_value(json!({
            "index": "main", "earliest": "-15m", "limit": 10
        }))
        .expect("deserializes");
        let result = s.splunk_search(Parameters(input)).await;
        assert_eq!(result.is_error, Some(true));
        let v = text_of(&result);
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["legal"], json!(["alpha", "beta"]));
    }

    #[tokio::test]
    async fn a_single_target_server_accepts_its_own_label_and_refuses_another() {
        let tok = token_file("t0k");
        let s = server(
            scripted_whoami("8.2.2.1", "idx-a.example.com"),
            Credential::Token {
                token_file: tok.path().to_path_buf(),
            },
        );
        let own = s
            .splunk_whoami(Parameters(WhoAmIInput {
                target: Some("alpha".into()),
            }))
            .await;
        assert_eq!(text_of(&own)["outcome"], "found");
        let other = s
            .splunk_whoami(Parameters(WhoAmIInput {
                target: Some("beta".into()),
            }))
            .await;
        assert_eq!(text_of(&other)["legal"], json!(["alpha"]));
    }
}
