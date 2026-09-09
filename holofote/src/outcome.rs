//! The four things a call can conclude, as the library's own sum — and the
//! typed reasons behind the two that are not about the world.
//!
//! [`Outcome`] is the crate's vocabulary; it converts into `kotae::Answer`
//! at the border (`From`), so the MCP server never chooses a discriminant
//! by hand. [`Blindness`] and [`Refusal`] are the typed causes: every
//! message an agent will read is a `thiserror` `Display`, so the words are
//! written once and the ★★ TYPED EMISSION rule holds without a `format!`.

use serde::Serialize;

use crate::auth::{CredentialError, LEGAL_CREDENTIAL_FORMS};
use crate::spl::SplError;
use crate::transport::TransportError;

/// What a call concluded. Generic over the found payload so each client
/// method returns its own shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<P> {
    /// Answered; here it is.
    Found(P),
    /// Answered; there is nothing. `of` names what was looked for.
    Empty {
        /// What was looked for.
        of: String,
    },
    /// The host answered and rejected the question, or the question failed
    /// validation before it was put. `legal` names what would be accepted.
    Refused {
        /// Why.
        because: String,
        /// What would have been accepted. Empty when not enumerable.
        legal: Vec<String>,
    },
    /// The question could not be put at all. Says nothing about the subject.
    Blind {
        /// What stopped it.
        because: String,
    },
}

impl<P> Outcome<P> {
    /// The discriminant, matching kotae's vocabulary.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Found(_) => "found",
            Self::Empty { .. } => "empty",
            Self::Refused { .. } => "refused",
            Self::Blind { .. } => "blind",
        }
    }

    /// `true` only for `Found` and `Empty` — the two that say something
    /// about the subject rather than about the attempt.
    #[must_use]
    pub const fn is_about_the_world(&self) -> bool {
        matches!(self, Self::Found(_) | Self::Empty { .. })
    }

    /// Map the found payload, leaving the other three arms untouched.
    pub fn map<Q>(self, f: impl FnOnce(P) -> Q) -> Outcome<Q> {
        match self {
            Self::Found(p) => Outcome::Found(f(p)),
            Self::Empty { of } => Outcome::Empty { of },
            Self::Refused { because, legal } => Outcome::Refused { because, legal },
            Self::Blind { because } => Outcome::Blind { because },
        }
    }
}

impl<P: Serialize> From<Outcome<P>> for kotae::Answer {
    fn from(o: Outcome<P>) -> Self {
        match o {
            Outcome::Found(p) => Self::found(&p),
            Outcome::Empty { of } => Self::empty(of),
            Outcome::Refused { because, legal } if legal.is_empty() => {
                Self::refused_flatly(because)
            }
            Outcome::Refused { because, legal } => Self::refused(because, legal),
            Outcome::Blind { because } => Self::blind(because),
        }
    }
}

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

    fn render<P: Serialize>(o: Outcome<P>) -> Value {
        let answer: kotae::Answer = o.into();
        serde_json::from_str(&answer.render()).expect("valid JSON")
    }

    /// The four arms render four different discriminants — and the typed
    /// `kind()` agrees with what a reader sees on the wire.
    #[test]
    fn the_four_outcomes_render_four_distinct_discriminants() {
        let outcomes: [Outcome<Value>; 4] = [
            Outcome::Found(json!({"rows": []})),
            Outcome::Empty {
                of: "events".into(),
            },
            Outcome::Refused {
                because: "bad".into(),
                legal: vec!["good".into()],
            },
            Outcome::Blind {
                because: "down".into(),
            },
        ];
        let mut seen = std::collections::HashSet::new();
        for o in outcomes {
            let kind = o.kind();
            let about_world = o.is_about_the_world();
            let v = render(o);
            assert_eq!(v["outcome"], kind);
            assert!(seen.insert(kind), "{kind} rendered twice");
            assert_eq!(about_world, matches!(kind, "found" | "empty"));
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn an_empty_legal_set_becomes_the_flat_refusal() {
        let v = render(Outcome::<()>::Refused {
            because: "x".into(),
            legal: vec![],
        });
        assert_eq!(v["outcome"], "refused");
        assert!(v["legal"].is_null());
        let w = render(Outcome::<()>::Refused {
            because: "x".into(),
            legal: vec!["a".into()],
        });
        assert_eq!(w["legal"], json!(["a"]));
    }

    #[test]
    fn failures_convert_to_the_matching_arm_with_their_legal_set() {
        let unauthorized: Outcome<()> = Failure::from(Refusal::Unauthorized {
            host: "splunk-a.example.com".into(),
            status: 401,
            route: "/services/server/info".into(),
        })
        .into();
        match &unauthorized {
            Outcome::Refused { because, legal } => {
                assert!(
                    because.contains("401") && because.contains("retrying cannot help"),
                    "{because}"
                );
                assert_eq!(legal.len(), LEGAL_CREDENTIAL_FORMS.len());
            }
            other => panic!("expected refused, got {}", other.kind()),
        }

        let blind: Outcome<()> = Failure::from(Blindness::Unreachable {
            source: TransportError::Connect {
                host: "splunk-a.example.com".into(),
                detail: "connection refused".into(),
                evidence: crate::transport::ConnectEvidence::Unprobed,
            },
        })
        .into();
        match &blind {
            Outcome::Blind { because } => assert!(because.contains("VPN"), "{because}"),
            other => panic!("expected blind, got {}", other.kind()),
        }

        let invalid: Outcome<()> =
            Failure::from(SplError::IllegalIndex { got: "a b".into() }).into();
        match &invalid {
            Outcome::Refused { legal, .. } => {
                assert_eq!(legal, &vec![crate::spl::IDENT_GRAMMAR.to_owned()]);
            }
            other => panic!("expected refused, got {}", other.kind()),
        }
    }

    #[test]
    fn map_touches_only_the_found_arm() {
        assert_eq!(Outcome::Found(2).map(|n| n * 2), Outcome::Found(4));
        assert_eq!(
            Outcome::<i32>::Empty { of: "x".into() }.map(|n| n * 2),
            Outcome::Empty { of: "x".into() }
        );
    }
}
