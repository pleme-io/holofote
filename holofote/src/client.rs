//! The observe-only Splunk client.
//!
//! Three questions, one transport, one credential. Every public method
//! returns an [`Outcome`] — never a bare `Result` — because the caller is an
//! agent and the four arms are the whole payload. Internally each method is
//! a `Result<_, Failure>` so the `?` operator carries a typed [`Blindness`]
//! or [`Refusal`] to the border, where [`Outcome::from`] renders it once.
//!
//! What this type deliberately lacks: any method that creates, edits or
//! deletes Splunk state other than the search jobs it itself dispatched.
//! There is no route for such a call ([`crate::route::Route`] is closed), so
//! a write is a compile error, not a runtime refusal.
//!
//! The job lifecycle is `create → poll → results → delete`, and the delete
//! runs on **every** path out of `poll`/`results` — success, empty, Splunk
//! failure, and the holofote-side timeout — because a job left behind holds
//! dispatch quota on the host until `auto_cancel` or `timeout` fires.

use std::fmt::{self, Write as _};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use handan::{RetryAdvice, Verdict};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::auth::{AuthHeader, Credential, CredentialError, Scheme, SessionKey, read_secret};
use crate::config::HolofoteConfig;
use crate::outcome::{Blindness, Failure, Outcome, Refusal};
use crate::route::{Absence, ResultsRoute, Route, Sid};
use crate::spl::{Search, SearchRequest};
use crate::tls::TlsPosture;
use crate::transport::{HttpRequest, HttpResponse, Transport, TransportError};
use crate::version::ServerVersion;

/// Who this client speaks for, echoed in every `whoami`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The display label — a tenant name, never a hostname doing double duty.
    pub label: String,
    /// The host as configured (`--host`), for messages.
    pub host: String,
    /// The TLS posture in force, so a degraded posture is visible in answers.
    pub tls_posture: TlsPosture,
}

/// Facts read once from `/services/server/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerFacts {
    version: ServerVersion,
    build: String,
    server_name: String,
}

/// The typed client over a [`Transport`].
pub struct SplunkClient<T: Transport> {
    transport: T,
    credential: Credential,
    config: HolofoteConfig,
    identity: Identity,
    session: Mutex<Option<SessionKey>>,
    server: Mutex<Option<ServerFacts>>,
}

// ── payloads ───────────────────────────────────────────────────────────

/// `splunk_whoami`'s found payload — the cheap reachability + credential probe.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WhoAmI {
    /// The configured label.
    pub label: String,
    /// The configured host.
    pub host: String,
    /// Splunk's version string.
    pub version: String,
    /// Splunk's build id.
    pub build: String,
    /// Splunk's `serverName`.
    pub server_name: String,
    /// The credential's username as Splunk sees it.
    pub username: String,
    /// The credential's roles.
    pub roles: Vec<String>,
    /// The TLS posture in force.
    pub tls_posture: String,
    /// `v1` or `v2` — derived from `version`.
    pub results_route: String,
}

/// One index as `/services/data/indexes` describes it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IndexSummary {
    /// The index name.
    pub name: String,
    /// `totalEventCount`, when Splunk reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_event_count: Option<u64>,
    /// `minTime`, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_time: Option<String>,
    /// `maxTime`, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time: Option<String>,
}

/// `splunk_indexes`'s found payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IndexList {
    /// The indexes returned, up to the limit.
    pub indexes: Vec<IndexSummary>,
    /// How many the host has in total, per `paging.total`.
    pub total: u64,
    /// `true` when `total` exceeds what was returned.
    pub truncated: bool,
}

/// `splunk_search`'s found payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SearchHits {
    /// The SPL exactly as rendered and sent. Its `head` count is one more
    /// than the requested limit — the probe row, see `truncated`.
    pub spl: String,
    /// The job id.
    pub sid: String,
    /// Splunk's `resultCount` for the job, capped at the requested limit
    /// (the probe row is not counted).
    pub result_count: u64,
    /// Field names, from the results body (or the first row when absent).
    pub fields: Vec<String>,
    /// The rows, each a flat field→value object. Never more than the
    /// requested limit.
    pub rows: Vec<Map<String, Value>>,
    /// `true` when the rows are not the whole answer: more rows matched
    /// than the limit (the probe row — one past the limit — came back), or
    /// Splunk finalized the search before it completed (`finalized`).
    pub truncated: bool,
    /// `true` when Splunk stopped the search at `max_time` before it
    /// completed. The rows are what had been produced by then.
    pub finalized: bool,
    /// Splunk's job messages (INFO / WARN / ERROR), when it left any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<String>,
}

// ── Splunk's wire shapes ───────────────────────────────────────────────

#[derive(Deserialize)]
struct Feed<C> {
    #[serde(default = "Vec::new")]
    entry: Vec<Entry<C>>,
    #[serde(default)]
    paging: Option<Paging>,
}

#[derive(Deserialize)]
struct Entry<C> {
    #[serde(default)]
    name: String,
    content: C,
}

#[derive(Deserialize)]
struct Paging {
    #[serde(default)]
    total: u64,
}

#[derive(Deserialize)]
struct LoginBody {
    #[serde(rename = "sessionKey")]
    session_key: String,
}

#[derive(Deserialize)]
struct ServerInfoContent {
    version: String,
    #[serde(default)]
    build: String,
    #[serde(rename = "serverName", default)]
    server_name: String,
}

#[derive(Deserialize)]
struct ContextContent {
    username: String,
    #[serde(default)]
    roles: Vec<String>,
}

/// Splunk renders many counters as strings in JSON; accept either.
#[derive(Deserialize)]
#[serde(untagged)]
enum Loose {
    Num(u64),
    Text(String),
}

impl Loose {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Num(n) => Some(*n),
            Self::Text(t) => t.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
struct IndexContent {
    #[serde(rename = "totalEventCount", default)]
    total_event_count: Option<Loose>,
    #[serde(rename = "minTime", default)]
    min_time: Option<String>,
    #[serde(rename = "maxTime", default)]
    max_time: Option<String>,
}

#[derive(Deserialize)]
struct JobCreated {
    sid: String,
}

#[derive(Deserialize)]
struct Message {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    text: String,
}

/// `KIND: text`, or just the text when Splunk gave no kind.
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.kind.is_empty() {
            f.write_str(&self.text)
        } else {
            write!(f, "{}: {}", self.kind, self.text)
        }
    }
}

#[derive(Deserialize)]
struct JobContent {
    #[serde(rename = "dispatchState", default)]
    dispatch_state: String,
    #[serde(rename = "isDone", default)]
    is_done: bool,
    #[serde(rename = "isFailed", default)]
    is_failed: bool,
    /// Splunk stopped the job before it completed — `max_time` fired, or
    /// someone finalized it. `isDone` is ALSO true on such a job, so the
    /// partial result set is indistinguishable from a complete one without
    /// this field.
    #[serde(rename = "isFinalized", default)]
    is_finalized: bool,
    #[serde(rename = "resultCount", default)]
    result_count: u64,
    #[serde(default)]
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct NamedField {
    name: String,
}

#[derive(Deserialize)]
struct ResultsBody {
    #[serde(default)]
    results: Vec<Map<String, Value>>,
    #[serde(default)]
    fields: Vec<NamedField>,
}

#[derive(Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    messages: Vec<Message>,
}

fn message_texts(messages: &[Message]) -> Vec<String> {
    messages.iter().map(Message::to_string).collect()
}

/// Retry advice, rendered for a `blind` message.
struct Advice(Option<RetryAdvice>);

impl fmt::Display for Advice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(RetryAdvice::After(d)) => write!(f, "retry after {}s", d.as_secs()),
            Some(RetryAdvice::At { unix_secs }) => write!(f, "retry at unix time {unix_secs}"),
            // `RetryAdvice` is `#[non_exhaustive]`: a form handan adds later
            // is still advice, rendered by the delay it resolves to now.
            Some(other) => write!(f, "retry after {}s", other.delay_now().as_secs()),
            None => f.write_str("no retry advice was given — the same request may succeed later"),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn json_query(route: Route) -> HttpRequest {
    HttpRequest::new(route).query("output_mode", "json")
}

impl<T: Transport> SplunkClient<T> {
    /// Build a client. `config` should already have passed
    /// [`HolofoteConfig::validate`].
    #[must_use]
    pub fn new(
        transport: T,
        credential: Credential,
        config: HolofoteConfig,
        identity: Identity,
    ) -> Self {
        Self {
            transport,
            credential,
            config,
            identity,
            session: Mutex::new(None),
            server: Mutex::new(None),
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn config(&self) -> &HolofoteConfig {
        &self.config
    }

    /// Who this client speaks for.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    // ── the three questions ───────────────────────────────────────────

    /// Version, build, server name, and who the credential is.
    pub async fn whoami(&self) -> Outcome<WhoAmI> {
        match self.whoami_inner().await {
            Ok(w) => Outcome::Found(w),
            Err(f) => f.into(),
        }
    }

    async fn whoami_inner(&self) -> Result<WhoAmI, Failure> {
        let facts = self.server_facts(true).await?;
        let resp = self.call(json_query(Route::CurrentContext)).await?;
        let feed: Feed<ContextContent> = self.parse(&Route::CurrentContext, &resp.body)?;
        let ctx = self.first_entry(&Route::CurrentContext, feed)?.content;
        Ok(WhoAmI {
            label: self.identity.label.clone(),
            host: self.identity.host.clone(),
            version: facts.version.to_string(),
            build: facts.build,
            server_name: facts.server_name,
            username: ctx.username,
            roles: ctx.roles,
            tls_posture: self.identity.tls_posture.to_string(),
            results_route: facts.version.results_route().to_string(),
        })
    }

    /// The indexes this credential can see. `limit` defaults to the
    /// configured `default_indexes_limit` and is **clamped** into
    /// `1..=max_results` — never `0`, which Splunk reads as *all*.
    pub async fn indexes(&self, limit: Option<u32>) -> Outcome<IndexList> {
        match self.indexes_inner(limit).await {
            Ok(list) if list.indexes.is_empty() => {
                let mut of = String::new();
                // Writing into a String cannot fail.
                let _ = write!(
                    of,
                    "indexes visible to this credential on {}",
                    self.identity.host
                );
                Outcome::Empty { of }
            }
            Ok(list) => Outcome::Found(list),
            Err(f) => f.into(),
        }
    }

    async fn indexes_inner(&self, limit: Option<u32>) -> Result<IndexList, Failure> {
        let count = limit
            .unwrap_or(self.config.default_indexes_limit)
            .clamp(1, self.config.max_results.max(1));
        let resp = self
            .call(json_query(Route::Indexes).query("count", count))
            .await?;
        let feed: Feed<IndexContent> = self.parse(&Route::Indexes, &resp.body)?;
        let total_hint = feed.paging.as_ref().map(|p| p.total);
        let indexes: Vec<IndexSummary> = feed
            .entry
            .into_iter()
            .map(|e| IndexSummary {
                name: e.name,
                total_event_count: e.content.total_event_count.as_ref().and_then(Loose::as_u64),
                min_time: e.content.min_time,
                max_time: e.content.max_time,
            })
            .collect();
        let returned = u64::try_from(indexes.len()).unwrap_or(u64::MAX);
        let total = total_hint.unwrap_or(returned);
        Ok(IndexList {
            indexes,
            total,
            truncated: total > returned,
        })
    }

    /// Validate `req` against the configured cap, then run it. A request
    /// that fails validation is `Refused` with its legal set and never
    /// reaches the host.
    pub async fn search(&self, req: SearchRequest) -> Outcome<SearchHits> {
        match Search::build(req, self.config.search_bounds()) {
            Ok(search) => self.search_typed(&search).await,
            Err(e) => Failure::from(e).into(),
        }
    }

    /// Run an already-typed search: create the job, poll it, fetch the
    /// results by the version-derived route, and release the job.
    pub async fn search_typed(&self, search: &Search) -> Outcome<SearchHits> {
        match self.run_search(search).await {
            Ok(Some(hits)) => Outcome::Found(hits),
            Ok(None) => {
                let mut of = String::from("events for `");
                // Writing into a String cannot fail.
                let _ = write!(
                    of,
                    "{search}` in {} on {}",
                    search.window(),
                    self.identity.host
                );
                Outcome::Empty { of }
            }
            Err(f) => f.into(),
        }
    }

    async fn run_search(&self, search: &Search) -> Result<Option<SearchHits>, Failure> {
        let facts = self.server_facts(false).await?;
        let route = facts.version.results_route();
        let sid = self.create_job(search).await?;
        let outcome = self.drive_job(&sid, search, route).await;
        self.release_job(&sid).await;
        outcome
    }

    // ── the job lifecycle ─────────────────────────────────────────────

    async fn create_job(&self, search: &Search) -> Result<Sid, Failure> {
        let req = json_query(Route::JobCreate)
            .form_plain("search", search)
            .form_plain("exec_mode", "normal")
            .form_plain("earliest_time", search.window().earliest())
            .form_plain("latest_time", search.window().latest())
            .form_plain("max_count", search.limit().probe())
            .form_plain("max_time", self.config.max_search_seconds)
            .form_plain("auto_cancel", self.config.job_auto_cancel_seconds)
            .form_plain("timeout", self.config.job_ttl_seconds);
        let resp = self.call(req).await?;
        let created: JobCreated = self.parse(&Route::JobCreate, &resp.body)?;
        Sid::try_from(created.sid).map_err(|e| {
            Blindness::Unreadable {
                host: self.identity.host.clone(),
                route: Route::JobCreate.to_string(),
                detail: e.to_string(),
            }
            .into()
        })
    }

    async fn drive_job(
        &self,
        sid: &Sid,
        search: &Search,
        route: ResultsRoute,
    ) -> Result<Option<SearchHits>, Failure> {
        let deadline = Instant::now() + self.config.max_search();
        let status_route = Route::JobStatus(sid.clone());
        let done = loop {
            let resp = self.call(json_query(status_route.clone())).await?;
            let feed: Feed<JobContent> = self.parse(&status_route, &resp.body)?;
            let job = self.first_entry(&status_route, feed)?.content;
            if job.is_failed {
                return Err(Refusal::JobFailed {
                    sid: sid.to_string(),
                    messages: message_texts(&job.messages),
                }
                .into());
            }
            if job.is_done {
                break job;
            }
            if Instant::now() >= deadline {
                return Err(Blindness::SearchTimeout {
                    sid: sid.to_string(),
                    seconds: self.config.max_search_seconds,
                    state: job.dispatch_state,
                }
                .into());
            }
            tokio::time::sleep(self.config.poll_interval()).await;
        };
        // Splunk's clock on `max_time` starts at dispatch, before the one
        // above, so on a real host it fires first: the job comes back
        // DONE and FINALIZED with whatever it had. No rows ⇒ a timeout,
        // never `empty`; rows ⇒ a partial answer, said so below.
        if done.is_finalized && done.result_count == 0 {
            return Err(Blindness::Finalized {
                sid: sid.to_string(),
                seconds: self.config.max_search_seconds,
                state: done.dispatch_state,
            }
            .into());
        }
        if done.result_count == 0 {
            return Ok(None);
        }
        let results_route = Route::job_results(sid.clone(), route);
        // `count` is the probe — one past the typed cap, never `0`, which
        // Splunk reads as ALL. If the probe row comes back, more rows
        // matched than the caller asked for; it is dropped before answering.
        let resp = self
            .call(
                json_query(results_route.clone())
                    .query("count", search.limit().probe())
                    .query("offset", 0u32),
            )
            .await?;
        let body: ResultsBody = self.parse(&results_route, &resp.body)?;
        let mut fields: Vec<String> = body.fields.into_iter().map(|f| f.name).collect();
        if fields.is_empty()
            && let Some(first) = body.results.first()
        {
            fields = first.keys().cloned().collect();
        }
        let limit = usize::try_from(search.limit().get()).unwrap_or(usize::MAX);
        let mut rows = body.results;
        let probe_answered = rows.len() > limit;
        rows.truncate(limit);
        Ok(Some(SearchHits {
            spl: search.to_string(),
            sid: sid.to_string(),
            result_count: done.result_count.min(u64::from(search.limit().get())),
            fields,
            rows,
            truncated: probe_answered || done.is_finalized,
            finalized: done.is_finalized,
            messages: message_texts(&done.messages),
        }))
    }

    /// Best-effort `DELETE` of a job holofote created. Failure is logged,
    /// never surfaced: the answer is about the search, and Splunk's own
    /// `auto_cancel` / `timeout` backstops still apply.
    async fn release_job(&self, sid: &Sid) {
        match self.call(json_query(Route::JobDelete(sid.clone()))).await {
            Ok(_) => tracing::debug!(sid = %sid, "search job released"),
            Err(e) => tracing::warn!(
                sid = %sid,
                error = %e,
                "search job could not be released; Splunk's auto_cancel/timeout backstops apply"
            ),
        }
    }

    // ── server facts ──────────────────────────────────────────────────

    async fn server_facts(&self, refresh: bool) -> Result<ServerFacts, Failure> {
        if !refresh && let Some(facts) = lock(&self.server).clone() {
            return Ok(facts);
        }
        let resp = self.call(json_query(Route::ServerInfo)).await?;
        let feed: Feed<ServerInfoContent> = self.parse(&Route::ServerInfo, &resp.body)?;
        let info = self.first_entry(&Route::ServerInfo, feed)?.content;
        let version =
            ServerVersion::try_from(info.version.as_str()).map_err(|e| Blindness::Unreadable {
                host: self.identity.host.clone(),
                route: Route::ServerInfo.to_string(),
                detail: e.to_string(),
            })?;
        let facts = ServerFacts {
            version,
            build: info.build,
            server_name: info.server_name,
        };
        *lock(&self.server) = Some(facts.clone());
        Ok(facts)
    }

    // ── authenticated transport ───────────────────────────────────────

    /// Send with the credential attached. On `401`/`403` the password path
    /// forgets its session, logs in again **once**, and retries **once**;
    /// a second rejection is a [`Refusal::Unauthorized`]. The token path
    /// has nothing to renew and refuses on the first.
    async fn call(&self, req: HttpRequest) -> Result<HttpResponse, Failure> {
        let mut renewed = false;
        loop {
            let header = self.authorization().await?;
            let resp = self
                .transport
                .send(req.clone().authorized(header))
                .await
                .map_err(|e| self.blind(e))?;
            let judgment = handan::judge(resp.status, resp.retry_after.as_deref());
            match judgment.verdict() {
                Verdict::Success => return Ok(resp),
                Verdict::Unauthorized
                    if !renewed && matches!(self.credential, Credential::Password { .. }) =>
                {
                    tracing::info!(route = %req.route, status = resp.status, "credential rejected; renewing the session once");
                    *lock(&self.session) = None;
                    renewed = true;
                }
                _ => return Err(self.failure_for(&req.route, &resp, judgment)),
            }
        }
    }

    async fn authorization(&self) -> Result<AuthHeader, Failure> {
        match &self.credential {
            Credential::None => Err(CredentialError::Absent.into()),
            Credential::Token { token_file } => {
                let token = read_secret(token_file)?;
                Ok(AuthHeader::render(Scheme::Bearer, &token))
            }
            Credential::Password {
                user_file,
                password_file,
            } => {
                if let Some(key) = lock(&self.session).clone() {
                    return Ok(key.header());
                }
                let user = read_secret(user_file)?;
                let password = read_secret(password_file)?;
                let key = self.login(user, password).await?;
                let header = key.header();
                *lock(&self.session) = Some(key);
                Ok(header)
            }
        }
    }

    async fn login(
        &self,
        user: Zeroizing<String>,
        password: Zeroizing<String>,
    ) -> Result<SessionKey, Failure> {
        let req = json_query(Route::Login)
            .form("username", user)
            .form("password", password);
        let resp = self.transport.send(req).await.map_err(|e| self.blind(e))?;
        let judgment = handan::judge(resp.status, resp.retry_after.as_deref());
        if judgment.verdict() != Verdict::Success {
            return Err(self.failure_for(&Route::Login, &resp, judgment));
        }
        // The body carries the key; keep it in zeroizing memory while it is
        // parsed, then move the key out.
        let body = Zeroizing::new(resp.body);
        let login: LoginBody = self.parse(&Route::Login, &body)?;
        tracing::info!(host = %self.identity.host, "session key obtained");
        Ok(SessionKey::new(login.session_key))
    }

    // ── classification ────────────────────────────────────────────────

    fn blind(&self, e: TransportError) -> Failure {
        match e {
            TransportError::Connect { .. } => Blindness::Unreachable { source: e }.into(),
            TransportError::Timeout { .. } => Blindness::RequestTimeout { source: e }.into(),
            TransportError::Tls { .. } => Blindness::Tls {
                source: e,
                posture: self.identity.tls_posture.to_string(),
            }
            .into(),
            other => Blindness::Transport(other).into(),
        }
    }

    /// Turn a non-success response into the typed failure its status
    /// means. The status is judged by `handan`; nothing here re-derives
    /// what a code means.
    fn failure_for(
        &self,
        route: &Route,
        resp: &HttpResponse,
        judgment: handan::Judgment,
    ) -> Failure {
        let host = self.identity.host.clone();
        match judgment.verdict() {
            Verdict::Unauthorized => Refusal::Unauthorized {
                host,
                status: resp.status,
                route: route.to_string(),
            }
            .into(),
            Verdict::Absent => match route.absence() {
                Absence::VersionPairing => Blindness::RouteAbsent {
                    host,
                    route: route.to_string(),
                    version: lock(&self.server)
                        .as_ref()
                        .map_or_else(|| "unknown".to_owned(), |f| f.version.to_string()),
                },
                Absence::JobGone => Blindness::JobGone {
                    host,
                    route: route.to_string(),
                },
                Absence::NotManagementApi => Blindness::NotManagementApi {
                    host,
                    route: route.to_string(),
                },
            }
            .into(),
            _ if resp.status == 400 => {
                let body: ErrorBody = serde_json::from_slice(&resp.body).unwrap_or_default();
                let mut messages = message_texts(&body.messages);
                if messages.is_empty() {
                    messages.push(String::from_utf8_lossy(&resp.body).into_owned());
                }
                Refusal::Search { host, messages }.into()
            }
            verdict => Blindness::Upstream {
                host,
                status: resp.status,
                verdict,
                route: route.to_string(),
                advice: Advice(judgment.advice()).to_string(),
            }
            .into(),
        }
    }

    fn parse<D: DeserializeOwned>(&self, route: &Route, body: &[u8]) -> Result<D, Failure> {
        serde_json::from_slice(body).map_err(|e| {
            Blindness::Unreadable {
                host: self.identity.host.clone(),
                route: route.to_string(),
                detail: e.to_string(),
            }
            .into()
        })
    }

    fn first_entry<C>(&self, route: &Route, feed: Feed<C>) -> Result<Entry<C>, Failure> {
        feed.entry.into_iter().next().ok_or_else(|| {
            Blindness::Unreadable {
                host: self.identity.host.clone(),
                route: route.to_string(),
                detail: "the feed carried no entry".to_owned(),
            }
            .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spl::{SortRequest, TermRequest};
    use crate::transport::{ConnectEvidence, MockTransport, RecordedCall, Scripted};
    use serde_json::json;
    use shikumi::TieredConfig as _;
    use std::io::Write as _;
    use std::path::PathBuf;

    const HOST: &str = "https://splunk-a.example.com:8089";

    struct Files {
        _user: tempfile::NamedTempFile,
        _password: tempfile::NamedTempFile,
        credential: Credential,
    }

    fn password_files(user: &str, password: &str) -> Files {
        let mut u = tempfile::NamedTempFile::new().expect("user file");
        u.write_all(user.as_bytes()).expect("write");
        let mut p = tempfile::NamedTempFile::new().expect("password file");
        p.write_all(password.as_bytes()).expect("write");
        let credential = Credential::Password {
            user_file: u.path().to_path_buf(),
            password_file: p.path().to_path_buf(),
        };
        Files {
            _user: u,
            _password: p,
            credential,
        }
    }

    fn identity() -> Identity {
        Identity {
            label: "alpha".into(),
            host: HOST.into(),
            tls_posture: TlsPosture::AcceptAny,
        }
    }

    fn fast_config() -> HolofoteConfig {
        HolofoteConfig {
            poll_interval_ms: 1,
            max_search_seconds: 5,
            ..HolofoteConfig::prescribed_default()
        }
    }

    fn client(
        mock: MockTransport,
        credential: Credential,
        config: HolofoteConfig,
    ) -> SplunkClient<MockTransport> {
        SplunkClient::new(mock, credential, config, identity())
    }

    fn login_ok(key: &str) -> (u16, Value) {
        (200, json!({ "sessionKey": key }))
    }

    fn server_info(version: &str) -> (u16, Value) {
        (
            200,
            json!({ "entry": [{ "name": "server-info", "content": {
                "version": version, "build": "ae6821b7c64b", "serverName": "idx-a.example.com" } }] }),
        )
    }

    fn context() -> (u16, Value) {
        (
            200,
            json!({ "entry": [{ "name": "context", "content": {
                "username": "observer", "roles": ["user"], "capabilities": ["search", "list_tokens_own"] } }] }),
        )
    }

    fn unauthorized() -> (u16, Value) {
        (
            401,
            json!({ "messages": [{ "type": "WARN", "text": "call not properly authenticated" }] }),
        )
    }

    fn sid() -> Sid {
        Sid::try_from("1757400000.42").expect("sid")
    }

    fn job_status(state: &str, done: bool, failed: bool, count: u64) -> (u16, Value) {
        (
            200,
            json!({ "entry": [{ "name": "job", "content": {
                "dispatchState": state, "isDone": done, "isFailed": failed,
                "resultCount": count, "eventCount": count,
                "messages": if failed { json!([{ "type": "FATAL", "text": "Error in 'stats' command" }]) } else { json!([]) } } }] }),
        )
    }

    /// The shape Splunk reports after `max_time` fires: DONE, not failed,
    /// FINALIZED, with whatever it had — and a message saying so.
    fn job_finalized(count: u64) -> (u16, Value) {
        (
            200,
            json!({ "entry": [{ "name": "job", "content": {
                "dispatchState": "DONE", "isDone": true, "isFailed": false, "isFinalized": true,
                "resultCount": count, "eventCount": count,
                "messages": [{ "type": "INFO", "text": "Search auto-finalized after time limit (5 seconds) reached." }] } }] }),
        )
    }

    fn results(rows: Value) -> (u16, Value) {
        let mut body = json!({ "preview": false, "init_offset": 0, "post_process_count": 0,
            "messages": [], "fields": [{ "name": "host" }, { "name": "count" }] });
        body["results"] = rows;
        (200, body)
    }

    fn request() -> SearchRequest {
        SearchRequest {
            index: "main".into(),
            terms: vec![TermRequest {
                field: Some("status".into()),
                op: None,
                value: "500".into(),
            }],
            earliest: "-15m".into(),
            latest: None,
            limit: 100,
            fields: vec![],
            stats_count_by: vec!["host".into()],
            sort: Some(SortRequest {
                field: "count".into(),
                descending: true,
            }),
        }
    }

    /// A whole scripted 8.2.2.1 host with one search job wired up.
    fn splunk_8(
        password_key: &str,
        status_replies: Vec<(u16, Value)>,
        result_rows: Value,
    ) -> MockTransport {
        let s = sid();
        MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok(password_key)])
            .reply_json(&Route::ServerInfo, vec![server_info("8.2.2.1")])
            .reply_json(&Route::CurrentContext, vec![context()])
            .reply_json(&Route::JobCreate, vec![(201, json!({ "sid": s.as_str() }))])
            .reply_json(&Route::JobStatus(s.clone()), status_replies)
            .reply_json(&Route::JobResultsV1(s.clone()), vec![results(result_rows)])
            .reply_json(&Route::JobDelete(s), vec![(200, json!({}))])
    }

    fn form_value<'a>(call: &'a RecordedCall, key: &str) -> Option<&'a str> {
        call.form
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn query_value<'a>(call: &'a RecordedCall, key: &str) -> Option<&'a str> {
        call.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn found<P>(o: Outcome<P>) -> P {
        match o {
            Outcome::Found(p) => p,
            other => panic!("expected found, got {}", other.kind()),
        }
    }

    fn refused<P>(o: Outcome<P>) -> (String, Vec<String>) {
        match o {
            Outcome::Refused { because, legal } => (because, legal),
            other => panic!("expected refused, got {}", other.kind()),
        }
    }

    fn blind<P>(o: Outcome<P>) -> String {
        match o {
            Outcome::Blind { because } => because,
            other => panic!("expected blind, got {}", other.kind()),
        }
    }

    // ── auth ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_password_path_logs_in_once_and_sends_the_splunk_scheme() {
        let files = password_files("observer\n", "s3cret\n");
        let mock = splunk_8("KEY1", vec![], json!([]));
        let c = client(mock, files.credential, fast_config());

        let who = found(c.whoami().await);
        assert_eq!(who.username, "observer");
        assert_eq!(who.version, "8.2.2.1");
        assert_eq!(who.results_route, "v1");
        assert_eq!(who.label, "alpha");
        assert_eq!(who.tls_posture, "accept-any");
        assert_eq!(who.roles, vec!["user".to_owned()]);
        assert_eq!(who.build, "ae6821b7c64b");
        assert_eq!(who.server_name, "idx-a.example.com");

        let logins = c.transport.calls_to(&Route::Login);
        assert_eq!(
            logins.len(),
            1,
            "exactly one login for two authenticated calls"
        );
        assert_eq!(
            form_value(&logins[0], "username"),
            Some("observer"),
            "trailing newline trimmed"
        );
        assert_eq!(form_value(&logins[0], "password"), Some("s3cret"));
        assert_eq!(query_value(&logins[0], "output_mode"), Some("json"));
        assert_eq!(
            logins[0].authorization, None,
            "login itself carries no Authorization"
        );

        for call in c
            .transport
            .calls_to(&Route::ServerInfo)
            .iter()
            .chain(c.transport.calls_to(&Route::CurrentContext).iter())
        {
            assert_eq!(call.authorization.as_deref(), Some("Splunk KEY1"));
        }
    }

    #[tokio::test]
    async fn a_401_renews_the_session_exactly_once_and_retries_once() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("STALE"), login_ok("FRESH")])
            .reply_json(
                &Route::ServerInfo,
                vec![unauthorized(), server_info("8.2.2.1")],
            )
            .reply_json(&Route::CurrentContext, vec![context()]);
        let c = client(mock, files.credential, fast_config());

        found(c.whoami().await);
        assert_eq!(c.transport.calls_to(&Route::Login).len(), 2);
        let infos = c.transport.calls_to(&Route::ServerInfo);
        assert_eq!(infos.len(), 2, "one rejected call, one retry");
        assert_eq!(infos[0].authorization.as_deref(), Some("Splunk STALE"));
        assert_eq!(infos[1].authorization.as_deref(), Some("Splunk FRESH"));
        // The renewed key is now cached: the next call does not log in again.
        assert_eq!(
            c.transport.calls_to(&Route::CurrentContext)[0]
                .authorization
                .as_deref(),
            Some("Splunk FRESH")
        );
        assert_eq!(c.transport.calls_to(&Route::Login).len(), 2);
    }

    #[tokio::test]
    async fn a_second_401_is_refused_naming_the_legal_credential_forms() {
        let files = password_files("observer", "wrong");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![unauthorized()]);
        let c = client(mock, files.credential, fast_config());

        let (because, legal) = refused(c.whoami().await);
        assert!(
            because.contains("401") && because.contains("/services/server/info"),
            "{because}"
        );
        assert_eq!(legal.len(), crate::auth::LEGAL_CREDENTIAL_FORMS.len());
        assert_eq!(
            c.transport.calls_to(&Route::Login).len(),
            2,
            "renewed once, not in a loop"
        );
        assert_eq!(
            c.transport.calls_to(&Route::ServerInfo).len(),
            2,
            "retried once, not in a loop"
        );
    }

    #[tokio::test]
    async fn a_rejected_login_is_refused_and_not_retried() {
        let files = password_files("observer", "wrong");
        let mock = MockTransport::new().reply_json(&Route::Login, vec![unauthorized()]);
        let c = client(mock, files.credential, fast_config());
        let (because, _) = refused(c.whoami().await);
        assert!(because.contains("/services/auth/login"), "{because}");
        assert_eq!(c.transport.calls_to(&Route::Login).len(), 1);
        assert!(c.transport.calls_to(&Route::ServerInfo).is_empty());
    }

    #[tokio::test]
    async fn the_token_path_sends_bearer_and_never_logs_in() {
        let mut t = tempfile::NamedTempFile::new().expect("token file");
        t.write_all(b"eyJ.token.value\n").expect("write");
        let mock = MockTransport::new()
            .reply_json(&Route::ServerInfo, vec![server_info("9.0.1")])
            .reply_json(&Route::CurrentContext, vec![context()]);
        let c = client(
            mock,
            Credential::Token {
                token_file: t.path().to_path_buf(),
            },
            fast_config(),
        );
        let who = found(c.whoami().await);
        assert_eq!(who.results_route, "v2");
        assert!(c.transport.calls_to(&Route::Login).is_empty());
        assert_eq!(
            c.transport.calls_to(&Route::ServerInfo)[0]
                .authorization
                .as_deref(),
            Some("Bearer eyJ.token.value")
        );
    }

    #[tokio::test]
    async fn a_token_401_is_refused_on_the_first_rejection() {
        let mut t = tempfile::NamedTempFile::new().expect("token file");
        t.write_all(b"expired").expect("write");
        let mock = MockTransport::new().reply_json(&Route::ServerInfo, vec![unauthorized()]);
        let c = client(
            mock,
            Credential::Token {
                token_file: t.path().to_path_buf(),
            },
            fast_config(),
        );
        refused(c.whoami().await);
        assert_eq!(
            c.transport.calls_to(&Route::ServerInfo).len(),
            1,
            "a token has nothing to renew"
        );
    }

    #[tokio::test]
    async fn no_credential_is_blind_naming_both_forms_and_touches_no_wire() {
        let c = client(MockTransport::new(), Credential::None, fast_config());
        let because = blind(c.whoami().await);
        for form in crate::auth::LEGAL_CREDENTIAL_FORMS {
            assert!(because.contains(form), "{because}");
        }
        assert!(
            c.transport.calls().is_empty(),
            "nothing may be sent without a credential"
        );
        assert_eq!(blind(c.indexes(None).await), because);
        blind(c.search(request()).await);
        assert!(c.transport.calls().is_empty());
    }

    #[tokio::test]
    async fn a_missing_credential_file_is_blind_naming_the_exact_path() {
        let c = client(
            MockTransport::new(),
            Credential::Password {
                user_file: PathBuf::from("/nope/holofote-user"),
                password_file: PathBuf::from("/nope/holofote-password"),
            },
            fast_config(),
        );
        let because = blind(c.whoami().await);
        assert!(because.contains("/nope/holofote-user"), "{because}");
        assert!(c.transport.calls().is_empty());
    }

    // ── search lifecycle ──────────────────────────────────────────────

    #[tokio::test]
    async fn a_search_on_8_x_creates_polls_reads_v1_and_releases_the_job() {
        let files = password_files("observer", "s3cret");
        let rows = json!([{ "host": "web-1", "count": "7" }, { "host": "web-2", "count": "3" }]);
        let mock = splunk_8(
            "K",
            vec![
                job_status("QUEUED", false, false, 0),
                job_status("RUNNING", false, false, 0),
                job_status("DONE", true, false, 2),
            ],
            rows.clone(),
        );
        let c = client(mock, files.credential, fast_config());

        let hits = found(c.search(request()).await);
        assert_eq!(
            hits.spl,
            "search index=\"main\" status=\"500\" | stats count by host | sort 101 -count | head 101"
        );
        assert_eq!(hits.sid, "1757400000.42");
        assert_eq!(hits.result_count, 2);
        assert_eq!(hits.fields, vec!["host".to_owned(), "count".to_owned()]);
        assert_eq!(serde_json::to_value(&hits.rows).expect("rows"), rows);
        assert!(!hits.truncated);
        assert!(!hits.finalized);
        assert!(hits.messages.is_empty());

        let create = &c.transport.calls_to(&Route::JobCreate)[0];
        assert_eq!(form_value(create, "search"), Some(hits.spl.as_str()));
        assert_eq!(form_value(create, "exec_mode"), Some("normal"));
        assert_eq!(form_value(create, "earliest_time"), Some("-15m"));
        assert_eq!(form_value(create, "latest_time"), Some("now"));
        assert_eq!(
            form_value(create, "max_count"),
            Some("101"),
            "the probe row"
        );
        assert_eq!(form_value(create, "max_time"), Some("5"));
        assert_eq!(form_value(create, "auto_cancel"), Some("120"));
        assert_eq!(form_value(create, "timeout"), Some("300"));
        assert_eq!(query_value(create, "output_mode"), Some("json"));

        assert_eq!(c.transport.calls_to(&Route::JobStatus(sid())).len(), 3);
        let read = c.transport.calls_to(&Route::JobResultsV1(sid()));
        assert_eq!(read.len(), 1);
        assert_eq!(query_value(&read[0], "count"), Some("101"), "the probe row");
        assert_eq!(query_value(&read[0], "offset"), Some("0"));
        assert!(
            c.transport.calls_to(&Route::JobResultsV2(sid())).is_empty(),
            "v2 is a 404 on 8.x"
        );

        // The DELETE is the last thing on the wire, after the results read.
        let calls = c.transport.calls();
        let last = calls.last().expect("calls");
        assert_eq!(
            (last.method, last.route.as_str()),
            (
                crate::route::Method::Delete,
                "/services/search/jobs/1757400000.42"
            )
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(sid())).len(), 1);
    }

    #[tokio::test]
    async fn a_search_on_9_x_reads_the_v2_route() {
        let files = password_files("observer", "s3cret");
        let s = sid();
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![server_info("9.0.1")])
            .reply_json(&Route::JobCreate, vec![(201, json!({ "sid": s.as_str() }))])
            .reply_json(
                &Route::JobStatus(s.clone()),
                vec![job_status("DONE", true, false, 1)],
            )
            .reply_json(
                &Route::JobResultsV2(s.clone()),
                vec![results(json!([{ "host": "a", "count": "1" }]))],
            )
            .reply_json(&Route::JobDelete(s.clone()), vec![(200, json!({}))]);
        let c = client(mock, files.credential, fast_config());
        let hits = found(c.search(request()).await);
        assert_eq!(hits.result_count, 1);
        assert_eq!(
            c.transport.calls_to(&Route::JobResultsV2(s.clone())).len(),
            1
        );
        assert!(
            c.transport
                .calls_to(&Route::JobResultsV1(s.clone()))
                .is_empty()
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(s)).len(), 1);
        // The version is read ONCE and cached for later searches.
        found(c.search(request()).await);
        assert_eq!(c.transport.calls_to(&Route::ServerInfo).len(), 1);
    }

    #[tokio::test]
    async fn zero_results_is_empty_naming_the_spl_and_the_job_is_released() {
        let files = password_files("observer", "s3cret");
        let mock = splunk_8("K", vec![job_status("DONE", true, false, 0)], json!([]));
        let c = client(mock, files.credential, fast_config());
        match c.search(request()).await {
            Outcome::Empty { of } => {
                assert!(of.contains("search index=\"main\""), "{of}");
                assert!(of.contains("[-15m, now]"), "{of}");
            }
            other => panic!("expected empty, got {}", other.kind()),
        }
        assert!(
            c.transport.calls_to(&Route::JobResultsV1(sid())).is_empty(),
            "no results read for an empty job"
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(sid())).len(), 1);
    }

    #[tokio::test]
    async fn a_failed_job_is_refused_with_splunks_messages_and_released() {
        let files = password_files("observer", "s3cret");
        let mock = splunk_8(
            "K",
            vec![
                job_status("RUNNING", false, false, 0),
                job_status("FAILED", true, true, 0),
            ],
            json!([]),
        );
        let c = client(mock, files.credential, fast_config());
        let (because, legal) = refused(c.search(request()).await);
        assert!(
            because.contains("FATAL: Error in 'stats' command"),
            "{because}"
        );
        assert!(!legal.is_empty());
        assert_eq!(c.transport.calls_to(&Route::JobDelete(sid())).len(), 1);
    }

    #[tokio::test]
    async fn a_poll_timeout_is_blind_and_still_releases_the_job() {
        let files = password_files("observer", "s3cret");
        let mock = splunk_8("K", vec![job_status("RUNNING", false, false, 0)], json!([]));
        let c = client(
            mock,
            files.credential,
            HolofoteConfig {
                max_search_seconds: 0,
                poll_interval_ms: 1,
                ..HolofoteConfig::prescribed_default()
            },
        );
        let because = blind(c.search(request()).await);
        assert!(
            because.contains("did not finish") && because.contains("RUNNING"),
            "{because}"
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(sid())).len(), 1);
        assert!(c.transport.calls_to(&Route::JobResultsV1(sid())).is_empty());
    }

    #[tokio::test]
    async fn a_400_fatal_on_create_is_refused_and_there_is_no_job_to_release() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![server_info("8.2.2.1")])
            .reply_json(
                &Route::JobCreate,
                vec![(400, json!({ "messages": [{ "type": "FATAL", "text": "Unknown search command 'x'." }] }))],
            );
        let c = client(mock, files.credential, fast_config());
        let (because, _) = refused(c.search(request()).await);
        assert!(because.contains("Unknown search command 'x'."), "{because}");
        assert!(
            c.transport
                .calls()
                .iter()
                .all(|c| c.method != crate::route::Method::Delete)
        );
    }

    #[tokio::test]
    async fn an_invalid_request_is_refused_before_touching_the_wire() {
        let files = password_files("observer", "s3cret");
        let c = client(MockTransport::new(), files.credential, fast_config());
        let (because, legal) = refused(
            c.search(SearchRequest {
                limit: 0,
                ..request()
            })
            .await,
        );
        assert!(because.contains("limit 0"), "{because}");
        assert_eq!(legal, vec!["1..=1000".to_owned()]);
        let (because, legal) = refused(
            c.search(SearchRequest {
                earliest: "soon".into(),
                ..request()
            })
            .await,
        );
        assert!(because.contains("soon"), "{because}");
        assert_eq!(legal.len(), crate::spl::TimeSpec::LEGAL_FORMS.len());
        assert!(c.transport.calls().is_empty());
    }

    /// `truncated` is a fact the wire carries. The SPL ends `| head 4` for a
    /// limit of 3, so the job holds at most 4 rows: when the 4th — the probe
    /// — comes back, more matched than the caller asked for; it is dropped
    /// and `truncated` is true. When exactly 3 come back, it is false.
    #[tokio::test]
    async fn the_probe_row_is_dropped_and_decides_truncation() {
        let files = password_files("observer", "s3cret");
        let four = json!([{ "host": "a" }, { "host": "b" }, { "host": "c" }, { "host": "d" }]);
        let mock = splunk_8("K", vec![job_status("DONE", true, false, 4)], four);
        let c = client(
            mock,
            files.credential.clone(),
            HolofoteConfig {
                max_results: 3,
                ..fast_config()
            },
        );
        let three = SearchRequest {
            limit: 3,
            ..request()
        };
        let hits = found(c.search(three.clone()).await);
        assert!(hits.truncated, "the probe row came back");
        assert_eq!(hits.rows.len(), 3, "the probe row is dropped");
        assert_eq!(hits.result_count, 3, "the probe row is not counted");
        assert!(hits.spl.ends_with("| head 4"), "{}", hits.spl);
        let read = &c.transport.calls_to(&Route::JobResultsV1(sid()))[0];
        assert_eq!(query_value(read, "count"), Some("4"));
        let create = &c.transport.calls_to(&Route::JobCreate)[0];
        assert_eq!(form_value(create, "max_count"), Some("4"));

        // Exactly the limit: the probe did not come back, so nothing is missing.
        let exact = json!([{ "host": "a" }, { "host": "b" }, { "host": "c" }]);
        let mock = splunk_8("K", vec![job_status("DONE", true, false, 3)], exact);
        let c = client(
            mock,
            files.credential,
            HolofoteConfig {
                max_results: 3,
                ..fast_config()
            },
        );
        let hits = found(c.search(three).await);
        assert!(!hits.truncated);
        assert_eq!(hits.rows.len(), 3);
        let (because, _) = refused(
            c.search(SearchRequest {
                limit: 4,
                ..request()
            })
            .await,
        );
        assert!(because.contains("exceeds"), "{because}");
    }

    /// Splunk's `max_time` fires before holofote's deadline on a real host
    /// and leaves a DONE + FINALIZED job. With no rows that is a timeout —
    /// `blind`, naming `max_time` — and never `empty`.
    #[tokio::test]
    async fn a_job_finalized_at_max_time_with_no_rows_is_blind_not_empty() {
        let files = password_files("observer", "s3cret");
        let mock = splunk_8("K", vec![job_finalized(0)], json!([]));
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.search(request()).await);
        assert!(
            because.contains("finalized") && because.contains("max_time=5s"),
            "{because}"
        );
        assert!(because.contains("not an empty window"), "{because}");
        assert!(
            c.transport.calls_to(&Route::JobResultsV1(sid())).is_empty(),
            "no results read for a job with no rows"
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(sid())).len(), 1);
    }

    /// With rows, a finalized job is a PARTIAL answer: found, but
    /// `truncated` and `finalized` say so, and Splunk's own message rides
    /// along.
    #[tokio::test]
    async fn a_job_finalized_at_max_time_with_rows_is_found_but_marked_partial() {
        let files = password_files("observer", "s3cret");
        let mock = splunk_8("K", vec![job_finalized(1)], json!([{ "host": "a" }]));
        let c = client(mock, files.credential, fast_config());
        let hits = found(c.search(request()).await);
        assert_eq!(hits.rows.len(), 1);
        assert!(hits.finalized);
        assert!(hits.truncated, "a finalized job is never the whole answer");
        assert_eq!(
            hits.messages,
            vec!["INFO: Search auto-finalized after time limit (5 seconds) reached.".to_owned()]
        );
        let rendered = serde_json::to_value(&hits).expect("json");
        assert_eq!(rendered["finalized"], true);
        assert_eq!(rendered["truncated"], true);
        assert!(rendered["messages"].is_array());
    }

    /// A request over a search bound is refused with the bound's YAML key
    /// before anything is sent.
    #[tokio::test]
    async fn a_request_over_a_search_bound_is_refused_by_key_before_the_wire() {
        let files = password_files("observer", "s3cret");
        let c = client(
            MockTransport::new(),
            files.credential,
            HolofoteConfig {
                max_terms: 1,
                ..fast_config()
            },
        );
        let (because, legal) = refused(
            c.search(SearchRequest {
                terms: vec![
                    TermRequest {
                        field: None,
                        op: None,
                        value: "a".into(),
                    },
                    TermRequest {
                        field: None,
                        op: None,
                        value: "b".into(),
                    },
                ],
                ..request()
            })
            .await,
        );
        assert!(because.contains("maxTerms"), "{because}");
        assert_eq!(
            legal,
            vec!["at most 1 terms in one search (maxTerms)".to_owned()]
        );
        assert!(c.transport.calls().is_empty());
    }

    // ── indexes ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn indexes_default_and_clamp_their_limit_and_report_truncation() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().reply_json(&Route::Login, vec![login_ok("K")]).reply_json(
            &Route::Indexes,
            vec![(
                200,
                json!({ "entry": [
                    { "name": "main", "content": { "totalEventCount": "12345", "minTime": "2026-01-01T00:00:00+00:00", "maxTime": "2026-09-09T00:00:00+00:00" } },
                    { "name": "_internal", "content": { "totalEventCount": 99 } }
                ], "paging": { "total": 7, "perPage": 2, "offset": 0 } }),
            )],
        );
        let c = client(
            mock,
            files.credential,
            HolofoteConfig {
                max_results: 50,
                default_indexes_limit: 2,
                ..fast_config()
            },
        );

        let list = found(c.indexes(None).await);
        assert_eq!(list.total, 7);
        assert!(list.truncated);
        assert_eq!(list.indexes[0].name, "main");
        assert_eq!(
            list.indexes[0].total_event_count,
            Some(12_345),
            "string counters are read"
        );
        assert_eq!(
            list.indexes[1].total_event_count,
            Some(99),
            "numeric counters too"
        );
        assert_eq!(
            list.indexes[0].min_time.as_deref(),
            Some("2026-01-01T00:00:00+00:00")
        );
        assert_eq!(
            query_value(&c.transport.calls_to(&Route::Indexes)[0], "count"),
            Some("2"),
            "default limit"
        );

        found(c.indexes(Some(5000)).await);
        assert_eq!(
            query_value(&c.transport.calls_to(&Route::Indexes)[1], "count"),
            Some("50"),
            "capped"
        );
        found(c.indexes(Some(0)).await);
        assert_eq!(
            query_value(&c.transport.calls_to(&Route::Indexes)[2], "count"),
            Some("1"),
            "never 0"
        );
    }

    #[tokio::test]
    async fn no_visible_indexes_is_empty_not_an_error() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(
                &Route::Indexes,
                vec![(200, json!({ "entry": [], "paging": { "total": 0 } }))],
            );
        let c = client(mock, files.credential, fast_config());
        match c.indexes(None).await {
            Outcome::Empty { of } => assert!(of.contains("indexes visible"), "{of}"),
            other => panic!("expected empty, got {}", other.kind()),
        }
    }

    // ── blindness ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_connect_failure_is_blind_and_names_the_vpn() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Connect {
                host: "splunk-a.example.com".into(),
                detail: "connection timed out".into(),
                evidence: ConnectEvidence::Unprobed,
            })],
        );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert!(
            because.contains("VPN") && because.contains("connection timed out"),
            "{because}"
        );
    }

    /// A request timeout means the host WAS reached: a different remedy
    /// from a connect failure, so it must not be rendered with the VPN one.
    #[tokio::test]
    async fn a_request_timeout_is_blind_naming_the_request_bound_not_the_vpn() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Timeout {
                host: "splunk-a.example.com".into(),
                detail: "operation timed out".into(),
            })],
        );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert!(
            because.contains("requestTimeoutMs") && because.contains("operation timed out"),
            "{because}"
        );
        assert!(
            !because.contains("VPN"),
            "a slow host is not an unreachable one: {because}"
        );
    }

    #[tokio::test]
    async fn a_tls_failure_is_blind_and_names_the_posture_flag() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Tls {
                host: "splunk-a.example.com".into(),
                detail: "invalid peer certificate: UnknownIssuer".into(),
                evidence: ConnectEvidence::Unprobed,
            })],
        );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert!(
            because.contains("--tls accept-any") && because.contains("UnknownIssuer"),
            "{because}"
        );
        assert!(
            !because.contains("VPN"),
            "a TLS failure is not a reachability failure: {because}"
        );
    }

    /// reqwest's own words for the measured chain — connect-class, no
    /// rustls error — as the transport reports them.
    const MEASURED_DETAIL: &str = "error sending request for url (https://splunk-a.example.com:8089/services/auth/login?output_mode=json)";

    /// The measured chain with plain TCP opening, under `system`: the
    /// transport classified it TLS on evidence, and the agent reads the
    /// posture flag, both remedies, and the evidence — never the VPN.
    #[tokio::test]
    async fn a_handshake_that_outran_the_connect_timeout_is_blind_naming_tls_with_the_evidence() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Tls {
                host: "splunk-a.example.com".into(),
                detail: MEASURED_DETAIL.into(),
                evidence: ConnectEvidence::TcpOpens {
                    host: "splunk-a.example.com".into(),
                    port: 8089,
                },
            })],
        );
        let c = SplunkClient::new(
            mock,
            files.credential,
            fast_config(),
            Identity {
                tls_posture: TlsPosture::System,
                ..identity()
            },
        );
        let because = blind(c.whoami().await);
        assert_eq!(
            because,
            "TLS handshake with splunk-a.example.com failed: error sending request for url (https://splunk-a.example.com:8089/services/auth/login?output_mode=json) (a plain TCP connection to splunk-a.example.com:8089 opens within the connect timeout, so the failure is past TCP — in the TLS handshake or just after) under `--tls system`. Splunk's stock certificate is self-signed: use `--tls accept-any` (degraded) or `--tls ca:<PEM>` with the private root"
        );
    }

    /// The same chain with plain TCP failing too: the VPN — and the message
    /// carries the evidence, so the agent can see the probe agreed.
    #[tokio::test]
    async fn a_connect_failure_with_tcp_also_failing_is_blind_naming_the_vpn_with_the_evidence() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Connect {
                host: "splunk-a.example.com".into(),
                detail: MEASURED_DETAIL.into(),
                evidence: ConnectEvidence::TcpClosed {
                    host: "splunk-a.example.com".into(),
                    port: 8089,
                },
            })],
        );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert_eq!(
            because,
            "could not connect to splunk-a.example.com: error sending request for url (https://splunk-a.example.com:8089/services/auth/login?output_mode=json) (a plain TCP connection to splunk-a.example.com:8089 also fails within the connect timeout). The usual cause is that the VPN this host lives behind is not connected — connect it and retry"
        );
        assert!(!because.contains("--tls"), "{because}");
    }

    /// Under `accept-any` a certificate cannot be the cause, so TCP opening
    /// is a plain transport failure: rendered transparently, with the
    /// evidence, and never the VPN message — TCP opened.
    #[tokio::test]
    async fn tcp_opening_under_accept_any_is_blind_with_the_evidence_and_not_the_vpn() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new().on(
            &Route::Login,
            vec![Scripted::Fail(TransportError::Other {
                host: "splunk-a.example.com".into(),
                detail: MEASURED_DETAIL.into(),
                evidence: ConnectEvidence::TcpOpens {
                    host: "splunk-a.example.com".into(),
                    port: 8089,
                },
            })],
        );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert_eq!(
            because,
            "request to splunk-a.example.com failed: error sending request for url (https://splunk-a.example.com:8089/services/auth/login?output_mode=json) (a plain TCP connection to splunk-a.example.com:8089 opens within the connect timeout, so the failure is past TCP — in the TLS handshake or just after)"
        );
        assert!(
            !because.contains("VPN") && !because.contains("--tls"),
            "{because}"
        );
    }

    #[tokio::test]
    async fn a_503_with_retry_after_is_blind_carrying_the_advice() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .on(
                &Route::ServerInfo,
                vec![Scripted::Reply(
                    HttpResponse::json(503, &json!({})).retry_after("30"),
                )],
            );
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert!(
            because.contains("503")
                && because.contains("server-error")
                && because.contains("retry after 30s"),
            "{because}"
        );
    }

    #[tokio::test]
    async fn a_404_on_a_results_route_is_blind_naming_the_version_pairing() {
        let files = password_files("observer", "s3cret");
        let s = sid();
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![server_info("9.0.1")])
            .reply_json(&Route::JobCreate, vec![(201, json!({ "sid": s.as_str() }))])
            .reply_json(
                &Route::JobStatus(s.clone()),
                vec![job_status("DONE", true, false, 1)],
            )
            .reply_json(&Route::JobResultsV2(s.clone()), vec![(404, json!({}))])
            .reply_json(&Route::JobDelete(s.clone()), vec![(200, json!({}))]);
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.search(request()).await);
        assert!(
            because.contains("no route") && because.contains("9.0.1"),
            "{because}"
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(s)).len(), 1);
    }

    /// A 404 on the job-status route is the JOB being gone, not a
    /// version-pairing bug; a 404 on a fixed route says the URL is not a
    /// Splunk management API at all. Neither may borrow the results-route
    /// message.
    #[tokio::test]
    async fn a_404_off_the_results_routes_is_blind_for_the_reason_the_route_implies() {
        let files = password_files("observer", "s3cret");
        let s = sid();
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![server_info("9.0.1")])
            .reply_json(&Route::JobCreate, vec![(201, json!({ "sid": s.as_str() }))])
            .reply_json(&Route::JobStatus(s.clone()), vec![(404, json!({}))])
            .reply_json(&Route::JobDelete(s.clone()), vec![(404, json!({}))]);
        let c = client(mock, files.credential.clone(), fast_config());
        let because = blind(c.search(request()).await);
        assert!(
            because.contains("no longer has the search job") && because.contains("re-run"),
            "{because}"
        );
        assert!(
            !because.contains("pairing"),
            "a reaped job is not a version bug: {because}"
        );
        assert_eq!(c.transport.calls_to(&Route::JobDelete(s)).len(), 1);

        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::Indexes, vec![(404, json!({}))]);
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.indexes(None).await);
        assert!(
            because.contains("management port") && because.contains("/services/data/indexes"),
            "{because}"
        );
        assert!(!because.contains("pairing"), "{because}");
    }

    #[tokio::test]
    async fn an_unparseable_version_is_blind_not_a_guessed_route() {
        let files = password_files("observer", "s3cret");
        let mock = MockTransport::new()
            .reply_json(&Route::Login, vec![login_ok("K")])
            .reply_json(&Route::ServerInfo, vec![server_info("eight-ish")]);
        let c = client(mock, files.credential, fast_config());
        let because = blind(c.whoami().await);
        assert!(because.contains("eight-ish"), "{because}");
    }

    /// The three non-found arms this client produces render to three
    /// different `outcome` discriminants through kotae.
    #[tokio::test]
    async fn empty_refused_and_blind_render_differently_at_the_border() {
        let files = password_files("observer", "s3cret");
        let empty = client(
            splunk_8("K", vec![job_status("DONE", true, false, 0)], json!([])),
            files.credential.clone(),
            fast_config(),
        )
        .search(request())
        .await;
        let refused = client(
            MockTransport::new(),
            files.credential.clone(),
            fast_config(),
        )
        .search(SearchRequest {
            limit: 0,
            ..request()
        })
        .await;
        let blind = client(MockTransport::new(), Credential::None, fast_config())
            .search(request())
            .await;

        let render = |o: Outcome<SearchHits>| -> Value {
            let a: kotae::Answer = o.into();
            serde_json::from_str(&a.render()).expect("json")
        };
        let (e, r, b) = (render(empty), render(refused), render(blind));
        assert_eq!(e["outcome"], "empty");
        assert_eq!(r["outcome"], "refused");
        assert_eq!(b["outcome"], "blind");
        assert_ne!(e.to_string(), r.to_string());
        assert_ne!(r.to_string(), b.to_string());
        assert_ne!(e.to_string(), b.to_string());
    }
}
