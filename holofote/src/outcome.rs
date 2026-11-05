//! The typed reasons behind the two outcomes that are not about the world.
//!
//! [`Outcome`] is kotae's four-arm sum, re-exported; the MCP server renders
//! it with `Outcome::render`, so no discriminant is chosen by hand.
//! [`Blindness`] and [`Refusal`] are the typed causes: every message an
//! agent will read is a `thiserror` `Display`, so the words are written once
//! and the ★★ TYPED EMISSION rule holds without a `format!`.

pub use kotae::{Outcome, OutcomeKind};

use crate::auth::{CredentialError, LEGAL_CREDENTIAL_FORMS};
use crate::spl::SplError;
use crate::transport::TransportError;

/// Why the question could not be put. Each arm names its remedy.
#[derive(Debug, thiserror::Error)]
pub enum Blindness {
    /// The host could not be reached at all: refused, unroutable, or the
    /// connect timed out.
    #[error(
        "{source}. The usual cause is that the VPN this host lives behind is not connected — connect it and retry"
    )]
    Unreachable {
        /// The transport's own account.
        #[source]
        source: TransportError,
    },
    /// The host WAS reached and then outran the request timeout. A
    /// different remedy from [`Blindness::Unreachable`]: the network is
    /// fine, the call is slow.
    #[error(
        "{source}. The host is reachable; this call outran requestTimeoutMs — retry, ask a narrower question, or raise requestTimeoutMs"
    )]
    RequestTimeout {
        /// The transport's own account.
        #[source]
        source: TransportError,
    },
    /// The TLS handshake failed under the configured posture.
    #[error(
        "{source} under `--tls {posture}`. Splunk's stock certificate is self-signed: use `--tls accept-any` (degraded) or `--tls ca:<PEM>` with the private root"
    )]
    Tls {
        /// The transport's own account.
        #[source]
        source: TransportError,
        /// The posture in force.
        posture: String,
    },
    /// Some other transport failure.
    #[error(transparent)]
    Transport(TransportError),
    /// The host answered with a status that says "not now" or "I broke".
    #[error("{host} answered HTTP {status} ({verdict}) on {route}; {advice}")]
    Upstream {
        /// The host as configured.
        host: String,
        /// The status.
        status: u16,
        /// handan's reading of it.
        verdict: handan::Verdict,
        /// The route that was being spoken.
        route: String,
        /// Retry advice, rendered.
        advice: String,
    },
    /// A results route the server does not have — the version-derived
    /// choice was wrong for this host. Only the two results routes reach
    /// this arm ([`crate::route::Absence::VersionPairing`]).
    #[error(
        "{host} has no route {route} (HTTP 404); the results route was derived from server version {version} — report this pairing"
    )]
    RouteAbsent {
        /// The host as configured.
        host: String,
        /// The missing route.
        route: String,
        /// The version the choice was derived from.
        version: String,
    },
    /// A job route answered 404: the job holofote created no longer exists
    /// on the host — reaped by `auto_cancel` / `timeout` before a poll, or
    /// lost by a search-head proxy. Not a version bug; re-run the search.
    #[error(
        "{host} no longer has the search job at {route} (HTTP 404) — it was reaped by auto_cancel/timeout or a search head proxy lost it; re-run the search"
    )]
    JobGone {
        /// The host as configured.
        host: String,
        /// The job route that answered 404.
        route: String,
    },
    /// A route every Splunk management API serves answered 404: the URL is
    /// not the management port, or a proxy in front of it drops the path.
    #[error(
        "{host} answered HTTP 404 on {route}, a route every Splunk management API serves — the URL may not point at the management port (8089), or a proxy in front of it does not pass this path"
    )]
    NotManagementApi {
        /// The host as configured.
        host: String,
        /// The route that answered 404.
        route: String,
    },
    /// No credential, or its file could not be read.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The search did not finish inside the holofote-side bound.
    #[error(
        "search {sid} did not finish within {seconds}s (last state {state}); the job was cancelled — narrow the window or raise maxSearchSeconds"
    )]
    SearchTimeout {
        /// The job.
        sid: String,
        /// The bound.
        seconds: u64,
        /// Splunk's last reported dispatch state.
        state: String,
    },
    /// Splunk finalized the job at `max_time` before it completed, and it
    /// had produced no rows. `isDone` is true on such a job, so without
    /// this arm it would read as `empty` — a finding about the window —
    /// when nobody knows what the window holds.
    #[error(
        "search {sid} was finalized by Splunk at max_time={seconds}s before it completed (last state {state}) and had produced no rows — a timeout, not an empty window; narrow the window or raise maxSearchSeconds"
    )]
    Finalized {
        /// The job.
        sid: String,
        /// The `max_time` that was sent.
        seconds: u64,
        /// Splunk's last reported dispatch state.
        state: String,
    },
    /// The body did not have the shape Splunk documents.
    #[error("{host} answered {route} with a body holofote could not read: {detail}")]
    Unreadable {
        /// The host as configured.
        host: String,
        /// The route.
        route: String,
        /// serde's reason.
        detail: String,
    },
}

/// Why the question was refused. Each arm knows its legal set.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The host rejected the credential (401/403), after the one re-login
    /// the password path is allowed.
    #[error(
        "{host} rejected the credential (HTTP {status}) on {route}; retrying cannot help — the user/password or token is not valid for this host, or its role lacks the capability"
    )]
    Unauthorized {
        /// The host as configured.
        host: String,
        /// 401 or 403.
        status: u16,
        /// The route.
        route: String,
    },
    /// Splunk answered 400 with FATAL messages about the search itself.
    #[error("{host} rejected the search (HTTP 400): {}", messages.join("; "))]
    Search {
        /// The host as configured.
        host: String,
        /// Splunk's `messages[].text`, FATAL and ERROR only.
        messages: Vec<String>,
    },
    /// The job ran and Splunk marked it failed.
    #[error("search job {sid} failed: {}", messages.join("; "))]
    JobFailed {
        /// The job.
        sid: String,
        /// Splunk's messages.
        messages: Vec<String>,
    },
    /// The request failed validation before it was sent.
    #[error(transparent)]
    Invalid(#[from] SplError),
    #[error("no target named {got:?}; this server serves: {}", known.join(", "))]
    UnknownTarget { got: String, known: Vec<String> },
    #[error("this server serves several targets and the call named none; pass `target`, one of: {}", known.join(", "))]
    TargetRequired { known: Vec<String> },
}

impl Refusal {
    /// What would have been accepted.
    #[must_use]
    pub fn legal(&self) -> Vec<String> {
        match self {
            Self::Unauthorized { .. } => LEGAL_CREDENTIAL_FORMS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            Self::Search { .. } | Self::JobFailed { .. } => vec![
                crate::spl::IDENT_GRAMMAR.to_owned(),
                "a search over an index and fields this role can see, in a bounded time window"
                    .to_owned(),
            ],
            Self::Invalid(e) => e.legal(),
            Self::UnknownTarget { known, .. } | Self::TargetRequired { known } => known.clone(),
        }
    }
}

/// The two ways a call ends without an answer about the world.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// See [`Blindness`].
    #[error(transparent)]
    Blind(#[from] Blindness),
    /// See [`Refusal`].
    #[error(transparent)]
    Refused(#[from] Refusal),
}

impl From<CredentialError> for Failure {
    fn from(e: CredentialError) -> Self {
        Self::Blind(Blindness::Credential(e))
    }
}

impl From<SplError> for Failure {
    fn from(e: SplError) -> Self {
        Self::Refused(Refusal::Invalid(e))
    }
}

impl<P> From<Failure> for Outcome<P> {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Blind(b) => Self::Blind {
                because: b.to_string(),
            },
            Failure::Refused(r) => Self::Refused {
                because: r.to_string(),
                legal: r.legal(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn render<P: serde::Serialize>(o: &Outcome<P>) -> Value {
        serde_json::from_str(&o.render()).expect("valid JSON")
    }

    fn sample(kind: OutcomeKind) -> Outcome<Value> {
        match kind {
            OutcomeKind::Found => Outcome::Found(json!({"rows": []})),
            OutcomeKind::Empty => Outcome::empty("events"),
            OutcomeKind::Refused => Outcome::refused("bad", ["good"]),
            OutcomeKind::Blind => Outcome::blind("down"),
        }
    }

    #[test]
    fn every_arm_renders_its_own_discriminant() {
        let mut seen = std::collections::HashSet::new();
        for kind in OutcomeKind::ALL {
            let o = sample(*kind);
            assert_eq!(o.kind(), *kind);
            let v = render(&o);
            assert_eq!(v["outcome"], kind.as_str());
            assert!(seen.insert(kind.as_str()), "{kind} rendered twice");
            assert_eq!(
                o.is_about_the_world(),
                matches!(kind, OutcomeKind::Found | OutcomeKind::Empty)
            );
        }
        assert_eq!(seen.len(), OutcomeKind::ALL.len());
    }

    #[test]
    fn an_empty_legal_set_becomes_the_flat_refusal() {
        let v = render(&Outcome::<()>::refused_flatly("x"));
        assert_eq!(v["outcome"], "refused");
        assert!(v["legal"].is_null());
        let w = render(&Outcome::<()>::refused("x", ["a"]));
        assert_eq!(w["legal"], json!(["a"]));
    }

    fn arms<P>(o: Outcome<P>) -> (OutcomeKind, String, Vec<String>) {
        match o {
            Outcome::Found(_) => (OutcomeKind::Found, String::new(), Vec::new()),
            Outcome::Empty { of } => (OutcomeKind::Empty, of, Vec::new()),
            Outcome::Refused { because, legal } => (OutcomeKind::Refused, because, legal),
            Outcome::Blind { because } => (OutcomeKind::Blind, because, Vec::new()),
        }
    }

    #[test]
    fn failures_convert_to_the_matching_arm_with_their_legal_set() {
        let (kind, because, legal) =
            arms(Outcome::<()>::from(Failure::from(Refusal::Unauthorized {
                host: "splunk-a.example.com".into(),
                status: 401,
                route: "/services/server/info".into(),
            })));
        assert_eq!(kind, OutcomeKind::Refused);
        assert!(
            because.contains("401") && because.contains("retrying cannot help"),
            "{because}"
        );
        assert_eq!(legal.len(), LEGAL_CREDENTIAL_FORMS.len());

        let (kind, because, _) = arms(Outcome::<()>::from(Failure::from(Blindness::Unreachable {
            source: TransportError::Connect {
                host: "splunk-a.example.com".into(),
                detail: "connection refused".into(),
                evidence: crate::transport::ConnectEvidence::Unprobed,
            },
        })));
        assert_eq!(kind, OutcomeKind::Blind);
        assert!(because.contains("VPN"), "{because}");

        let (kind, _, legal) = arms(Outcome::<()>::from(Failure::from(SplError::IllegalIndex {
            got: "a b".into(),
        })));
        assert_eq!(kind, OutcomeKind::Refused);
        assert_eq!(legal, vec![crate::spl::IDENT_GRAMMAR.to_owned()]);
    }

    #[test]
    fn map_touches_only_the_found_arm() {
        for kind in OutcomeKind::ALL {
            let before = sample(*kind);
            let after = before.clone().map(|_| 7_u8);
            let expected = match before {
                Outcome::Found(_) => Outcome::Found(7_u8),
                Outcome::Empty { of } => Outcome::Empty { of },
                Outcome::Refused { because, legal } => Outcome::Refused { because, legal },
                Outcome::Blind { because } => Outcome::Blind { because },
            };
            assert_eq!(after, expected);
        }
    }
}
