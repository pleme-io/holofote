//! The transport seam: one trait, one real implementation, one test double.
//!
//! Every byte holofote sends or receives passes through [`Transport::send`].
//! The client above it never names `reqwest`, so all of its logic — login,
//! the single re-login, the job lifecycle, the version-derived route — is
//! exercised against [`MockTransport`] with zero network. The real
//! [`ReqwestTransport`] owns exactly three concerns: turning a [`Route`]
//! into a URL, honouring the [`TlsPosture`], and classifying a failure by
//! **type** (a `rustls::Error` found in the error chain is a TLS failure;
//! `is_connect()` / `is_timeout()` are reachability) so the client can say
//! *why* it was blind without matching on English prose.

#[cfg(any(test, feature = "mock"))]
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
#[cfg(any(test, feature = "mock"))]
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AuthHeader, LEGAL_CREDENTIAL_FORMS};
pub use crate::route::Method;
use crate::route::Route;
use crate::tls::TlsPosture;

/// Hand a secret to the HTTP stack as a buffer that zeroizes when the
/// stack releases it. `Bytes::from_owner` keeps the allocation and drops
/// the owner — the `Zeroizing` — when the last reference goes, so the
/// header value and the login body are wiped by the same rule as every
/// other secret here. What hyper copies into its own write buffer is
/// outside our reach; that copy is the honest limit of any HTTP client,
/// noted rather than hidden.
fn zeroizing_bytes<T>(secret: Zeroizing<T>) -> Bytes
where
    T: AsRef<[u8]> + Zeroize + Send + 'static,
{
    Bytes::from_owner(secret)
}

/// A boxed, sendable future — the object-safe return shape of [`Transport::send`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One request, before it becomes bytes.
///
/// The method is derived from the route ([`Route::method`]) — a caller
/// cannot pair them wrongly. Form values and the authorization header live
/// in zeroizing memory; `Debug` redacts both.
#[derive(Clone)]
pub struct HttpRequest {
    /// Derived from `route`.
    pub method: Method,
    /// Where.
    pub route: Route,
    /// Query pairs, appended in order.
    pub query: Vec<(String, String)>,
    /// Form pairs (`application/x-www-form-urlencoded`). Empty ⇒ no body.
    pub form: Vec<(String, Zeroizing<String>)>,
    /// The rendered `Authorization` value, if the route is authenticated.
    pub authorization: Option<AuthHeader>,
}

impl HttpRequest {
    /// A bare request for `route`, with the method the route dictates.
    #[must_use]
    pub fn new(route: Route) -> Self {
        Self {
            method: route.method(),
            route,
            query: Vec::new(),
            form: Vec::new(),
            authorization: None,
        }
    }

    /// Append a query pair.
    #[must_use]
    pub fn query(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Append a form pair. The value moves into zeroizing memory.
    #[must_use]
    pub fn form(mut self, key: &str, value: Zeroizing<String>) -> Self {
        self.form.push((key.to_owned(), value));
        self
    }

    /// Append a non-secret form pair.
    #[must_use]
    pub fn form_plain(self, key: &str, value: impl fmt::Display) -> Self {
        self.form(key, Zeroizing::new(value.to_string()))
    }

    /// Attach the rendered `Authorization` header.
    #[must_use]
    pub fn authorized(mut self, header: AuthHeader) -> Self {
        self.authorization = Some(header);
        self
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("route", &self.route.to_string())
            .field("query", &self.query)
            .field(
                "form_keys",
                &self
                    .form
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("authorization", &self.authorization)
            .finish()
    }
}

/// What came back: the status, the one header the judge needs, the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// The raw `Retry-After` header, if present — fed to [`handan::judge`].
    pub retry_after: Option<String>,
    /// The body, unparsed.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A JSON body with the given status — the shape every test scripts.
    #[must_use]
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            retry_after: None,
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    /// Attach a `Retry-After` value.
    #[must_use]
    pub fn retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}

/// Why no response came back at all. Each arm is a different remedy, and
/// the client renders each as a different `blind`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The host could not be reached — refused, unroutable, or the connect
    /// timed out. The usual cause is a VPN that is not up.
    #[error("could not connect to {host}: {detail}")]
    Connect {
        /// The host as configured.
        host: String,
        /// The OS / client's own words.
        detail: String,
    },
    /// The host was reached but did not answer within the request timeout.
    #[error("{host} did not answer within the request timeout: {detail}")]
    Timeout {
        /// The host as configured.
        host: String,
        /// The client's own words.
        detail: String,
    },
    /// The TLS handshake failed — a certificate the current posture does
    /// not trust.
    #[error("TLS handshake with {host} failed: {detail}")]
    Tls {
        /// The host as configured.
        host: String,
        /// rustls's own words.
        detail: String,
    },
    /// Anything else the client could not classify.
    #[error("request to {host} failed: {detail}")]
    Other {
        /// The host as configured.
        host: String,
        /// The client's own words.
        detail: String,
    },
    /// Only the mock produces this: a request no test scripted.
    #[error("no scripted response for {method} {route}")]
    Unscripted {
        /// The verb.
        method: Method,
        /// The rendered route.
        route: String,
    },
}

/// The seam. Object-safe, so a client can hold `Box<dyn Transport>`.
pub trait Transport: Send + Sync {
    /// Put one request and await its response.
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        (**self).send(req)
    }
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        (**self).send(req)
    }
}

// ── the real one ───────────────────────────────────────────────────────

/// Connect and request deadlines, from the deployment config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP connect + TLS handshake budget.
    pub connect: Duration,
    /// Whole-request budget.
    pub request: Duration,
}

/// Why the real transport could not be built.
#[derive(Debug, thiserror::Error)]
pub enum TransportBuildError {
    /// `--tls ca:<path>` named a file that could not be read.
    #[error("CA bundle {path} could not be read: {source}")]
    CaUnreadable {
        /// The path given.
        path: std::path::PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// `--tls ca:<path>` named a file that is not PEM.
    #[error("CA bundle {path} is not a PEM certificate: {detail}")]
    CaNotPem {
        /// The path given.
        path: std::path::PathBuf,
        /// reqwest's own words.
        detail: String,
    },
    /// The HTTP client refused its configuration.
    #[error("HTTP client could not be built: {detail}")]
    Client {
        /// reqwest's own words.
        detail: String,
    },
    /// The base URL carried a username or password. Refused, and the URL
    /// is deliberately NOT echoed: reqwest would turn userinfo into a
    /// `Basic` header beside the real one, and every answer's `host` field
    /// would carry the password.
    #[error(
        "the base URL carries a username or password; a credential is supplied only as {}",
        LEGAL_CREDENTIAL_FORMS.join(" | ")
    )]
    CredentialInUrl,
}

/// The production transport: reqwest over rustls.
pub struct ReqwestTransport {
    client: reqwest::Client,
    base: url::Url,
    host: String,
}

impl ReqwestTransport {
    /// Build against `base` (scheme, host and port; e.g.
    /// `https://splunk.example.com:8089`) under `tls`.
    pub fn new(
        base: url::Url,
        tls: &TlsPosture,
        timeouts: Timeouts,
    ) -> Result<Self, TransportBuildError> {
        if !base.username().is_empty() || base.password().is_some() {
            return Err(TransportBuildError::CredentialInUrl);
        }
        let mut builder = reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.request)
            .use_rustls_tls();
        match tls {
            TlsPosture::System => {}
            TlsPosture::AcceptAny => {
                builder = builder
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true);
            }
            TlsPosture::Ca(path) => {
                let pem =
                    std::fs::read(path).map_err(|source| TransportBuildError::CaUnreadable {
                        path: path.clone(),
                        source,
                    })?;
                let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                    TransportBuildError::CaNotPem {
                        path: path.clone(),
                        detail: e.to_string(),
                    }
                })?;
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build().map_err(|e| TransportBuildError::Client {
            detail: e.to_string(),
        })?;
        let host = base.host_str().unwrap_or_default().to_owned();
        Ok(Self { client, base, host })
    }

    fn url_for(&self, req: &HttpRequest) -> url::Url {
        let mut url = self.base.clone();
        url.set_path(&req.route.to_string());
        url.set_query(None);
        if !req.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(req.query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        url
    }

    fn classify(&self, e: &reqwest::Error) -> TransportError {
        let host = self.host.clone();
        let detail = e.to_string();
        if chain_holds_tls_error(e) {
            TransportError::Tls { host, detail }
        } else if e.is_timeout() {
            TransportError::Timeout { host, detail }
        } else if e.is_connect() {
            TransportError::Connect { host, detail }
        } else {
            TransportError::Other { host, detail }
        }
    }
}

/// Walk an error's `source()` chain looking for a `rustls::Error` — either
/// directly or wrapped in an `io::Error`, which is how `tokio-rustls`
/// surfaces it. Typed, not a string match.
pub fn chain_holds_tls_error(root: &(dyn std::error::Error + 'static)) -> bool {
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = Some(root);
    while let Some(err) = cursor {
        if err.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            && inner.downcast_ref::<rustls::Error>().is_some()
        {
            return true;
        }
        cursor = err.source();
    }
    false
}

impl Transport for ReqwestTransport {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let url = self.url_for(&req);
            let method = match req.method {
                Method::Get => reqwest::Method::GET,
                Method::Post => reqwest::Method::POST,
                Method::Delete => reqwest::Method::DELETE,
            };
            let mut builder = self.client.request(method, url);
            if let Some(auth) = &req.authorization {
                // One copy, into zeroizing memory, released by hyper.
                let secret = Zeroizing::new(auth.as_str().as_bytes().to_vec());
                let mut value =
                    reqwest::header::HeaderValue::from_maybe_shared(zeroizing_bytes(secret))
                        .map_err(|e| TransportError::Other {
                            host: self.host.clone(),
                            detail: e.to_string(),
                        })?;
                // Marks the value so reqwest/hyper debug output redacts it.
                value.set_sensitive(true);
                builder = builder.header(reqwest::header::AUTHORIZATION, value);
            }
            if !req.form.is_empty() {
                // The encoded body is built in zeroizing memory and handed
                // over as-is — no plain copy is ever made here.
                let mut encoded = Zeroizing::new(String::new());
                {
                    let mut ser = url::form_urlencoded::Serializer::new(&mut *encoded);
                    for (k, v) in &req.form {
                        ser.append_pair(k, v);
                    }
                    ser.finish();
                }
                builder = builder
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        reqwest::header::HeaderValue::from_static(
                            "application/x-www-form-urlencoded",
                        ),
                    )
                    .body(zeroizing_bytes(encoded));
            }
            let response = builder.send().await.map_err(|e| self.classify(&e))?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = response
                .bytes()
                .await
                .map_err(|e| self.classify(&e))?
                .to_vec();
            Ok(HttpResponse {
                status,
                retry_after,
                body,
            })
        })
    }
}

// ── the test double ────────────────────────────────────────────────────
//
// Compiled only for this crate's own tests or under the `mock` feature.
// `RecordedCall` copies every form value and the Authorization value into
// plain `String`s — that is its whole purpose — so the shipped library
// carries no such path unless a consumer opts in to script a transport.

/// One scripted reply.
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone)]
pub enum Scripted {
    /// Answer with this response.
    Reply(HttpResponse),
    /// Fail the transport with this error.
    Fail(TransportError),
}

/// What the mock saw, with secrets copied out as plain strings — this is a
/// test double and the whole point is to assert on them.
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    /// The verb.
    pub method: Method,
    /// The rendered route.
    pub route: String,
    /// Query pairs as sent.
    pub query: Vec<(String, String)>,
    /// Form pairs as sent.
    pub form: Vec<(String, String)>,
    /// The `Authorization` value as sent.
    pub authorization: Option<String>,
}

/// A transport that answers from a script keyed by `(method, route)`.
///
/// Replies for one key are consumed in order; the **last** reply sticks, so
/// a poll loop can be scripted as `[running, running, done]` and any extra
/// poll keeps seeing `done`. A key with no script yields
/// [`TransportError::Unscripted`], which a test will see as a loud failure.
#[cfg(any(test, feature = "mock"))]
#[derive(Default)]
pub struct MockTransport {
    scripts: Mutex<HashMap<(Method, String), VecDeque<Scripted>>>,
    calls: Mutex<Vec<RecordedCall>>,
}

#[cfg(any(test, feature = "mock"))]
impl MockTransport {
    /// An empty script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script replies for `route`.
    #[must_use]
    pub fn on(self, route: &Route, replies: Vec<Scripted>) -> Self {
        self.scripts
            .lock()
            .expect("mock script lock")
            .insert((route.method(), route.to_string()), replies.into());
        self
    }

    /// Script JSON replies for `route`, in order.
    #[must_use]
    pub fn reply_json(self, route: &Route, replies: Vec<(u16, serde_json::Value)>) -> Self {
        self.on(
            route,
            replies
                .into_iter()
                .map(|(status, body)| Scripted::Reply(HttpResponse::json(status, &body)))
                .collect(),
        )
    }

    /// Everything sent so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("mock call lock").clone()
    }

    /// The calls that went to `route`.
    #[must_use]
    pub fn calls_to(&self, route: &Route) -> Vec<RecordedCall> {
        let path = route.to_string();
        self.calls()
            .into_iter()
            .filter(|c| c.method == route.method() && c.route == path)
            .collect()
    }
}

#[cfg(any(test, feature = "mock"))]
impl Transport for MockTransport {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        let route = req.route.to_string();
        self.calls
            .lock()
            .expect("mock call lock")
            .push(RecordedCall {
                method: req.method,
                route: route.clone(),
                query: req.query.clone(),
                form: req
                    .form
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                    .collect(),
                authorization: req.authorization.as_ref().map(|a| a.as_str().to_owned()),
            });
        let next = {
            let mut scripts = self.scripts.lock().expect("mock script lock");
            scripts
                .get_mut(&(req.method, route.clone()))
                .and_then(|queue| {
                    if queue.len() > 1 {
                        queue.pop_front()
                    } else {
                        queue.front().cloned()
                    }
                })
        };
        Box::pin(async move {
            match next {
                Some(Scripted::Reply(r)) => Ok(r),
                Some(Scripted::Fail(e)) => Err(e),
                None => Err(TransportError::Unscripted {
                    method: req.method,
                    route,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_takes_its_method_from_the_route_and_redacts_secrets() {
        let req = HttpRequest::new(Route::Login)
            .query("output_mode", "json")
            .form("username", Zeroizing::new("alice".into()))
            .form("password", Zeroizing::new("hunter2".into()))
            .authorized(AuthHeader::render(crate::auth::Scheme::Bearer, "t0k"));
        assert_eq!(req.method, Method::Post);
        assert_eq!(HttpRequest::new(Route::Indexes).method, Method::Get);
        let shown = format!("{req:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("t0k"),
            "{shown}"
        );
        assert!(shown.contains("password"), "keys stay visible: {shown}");
    }

    /// A secret handed to the HTTP stack rides a buffer that is wiped when
    /// the stack lets go of it: the bytes are the secret while held, and
    /// the owner is dropped — zeroized — with the last reference.
    #[test]
    fn a_secret_crosses_into_the_http_stack_as_a_zeroizing_buffer() {
        let b = zeroizing_bytes(Zeroizing::new(b"hunter2".to_vec()));
        assert_eq!(&b[..], b"hunter2");
        let value = reqwest::header::HeaderValue::from_maybe_shared(zeroizing_bytes(
            Zeroizing::new(String::from("Splunk k3y")),
        ))
        .expect("visible ASCII");
        assert_eq!(value.as_bytes(), b"Splunk k3y");
        let body: reqwest::Body = zeroizing_bytes(Zeroizing::new(String::from("a=b"))).into();
        assert_eq!(body.as_bytes(), Some(&b"a=b"[..]));
    }

    /// A base URL carrying userinfo is refused at construction, and the
    /// refusal does not echo the URL — so the password reaches neither a
    /// `Basic` header nor a log line.
    #[test]
    fn a_base_url_carrying_a_credential_is_refused_without_echoing_it() {
        for url in [
            "https://observer:hunter2@splunk-a.example.com:8089",
            "https://observer@splunk-a.example.com:8089",
            "https://:hunter2@splunk-a.example.com:8089",
        ] {
            let err = ReqwestTransport::new(
                url::Url::parse(url).expect("url"),
                &TlsPosture::System,
                Timeouts {
                    connect: Duration::from_secs(1),
                    request: Duration::from_secs(1),
                },
            )
            .err()
            .unwrap_or_else(|| panic!("{url} must be refused"));
            assert!(matches!(err, TransportBuildError::CredentialInUrl), "{err}");
            let msg = err.to_string();
            assert!(
                !msg.contains("hunter2") && !msg.contains("observer"),
                "{msg}"
            );
            for form in LEGAL_CREDENTIAL_FORMS {
                assert!(msg.contains(form), "{msg}");
            }
        }
    }

    #[tokio::test]
    async fn the_mock_replays_in_order_and_the_last_reply_sticks() {
        let mock = MockTransport::new().reply_json(
            &Route::ServerInfo,
            vec![(500, json!({"n": 1})), (200, json!({"n": 2}))],
        );
        let statuses: Vec<u16> = {
            let mut v = Vec::new();
            for _ in 0..3 {
                v.push(
                    mock.send(HttpRequest::new(Route::ServerInfo))
                        .await
                        .expect("scripted")
                        .status,
                );
            }
            v
        };
        assert_eq!(statuses, [500, 200, 200]);
        assert_eq!(mock.calls_to(&Route::ServerInfo).len(), 3);
        let unscripted = mock
            .send(HttpRequest::new(Route::Indexes))
            .await
            .expect_err("nothing scripted");
        assert!(matches!(unscripted, TransportError::Unscripted { .. }));
    }

    /// The TLS classifier finds a `rustls::Error` by TYPE, both bare and
    /// wrapped the way tokio-rustls wraps it — and does not fire on a plain
    /// connection refusal.
    #[test]
    fn a_tls_error_is_recognised_by_type_anywhere_in_the_chain() {
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let bare = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert!(chain_holds_tls_error(&bare));

        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
        );
        assert!(chain_holds_tls_error(&wrapped));

        assert!(chain_holds_tls_error(&Outer(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::HandshakeNotComplete,
        ))));

        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!chain_holds_tls_error(&refused));
        assert!(!chain_holds_tls_error(&Outer(refused)));
    }

    #[test]
    fn the_real_transport_builds_a_url_from_route_and_query() {
        let t = ReqwestTransport::new(
            url::Url::parse("https://splunk-a.example.com:8089").expect("url"),
            &TlsPosture::AcceptAny,
            Timeouts {
                connect: Duration::from_millis(10),
                request: Duration::from_millis(10),
            },
        )
        .expect("builds");
        let sid = crate::route::Sid::try_from("17.5").expect("sid");
        let req = HttpRequest::new(Route::JobResultsV1(sid))
            .query("output_mode", "json")
            .query("count", 100u32)
            .query("offset", 0u32);
        assert_eq!(
            t.url_for(&req).as_str(),
            "https://splunk-a.example.com:8089/services/search/jobs/17.5/results?output_mode=json&count=100&offset=0"
        );
        assert_eq!(t.host, "splunk-a.example.com");
    }

    #[test]
    fn a_missing_ca_bundle_is_a_typed_build_error() {
        let err = ReqwestTransport::new(
            url::Url::parse("https://splunk-b.example.com:8089").expect("url"),
            &TlsPosture::Ca("/nope/holofote-root.pem".into()),
            Timeouts {
                connect: Duration::from_secs(1),
                request: Duration::from_secs(1),
            },
        )
        .err()
        .expect("fails");
        assert!(matches!(err, TransportBuildError::CaUnreadable { .. }));
        assert!(err.to_string().contains("/nope/holofote-root.pem"));
    }
}
