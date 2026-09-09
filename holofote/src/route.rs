//! The closed set of Splunk REST routes holofote can speak, and the one
//! place their paths are rendered.
//!
//! A route is an enum arm, never a string a caller assembles. Two things
//! follow. The HTTP method is a *property of the arm* ([`Route::method`]),
//! so a `DELETE` against the status route or a `GET` against login has no
//! representation. And a search id reaches a path only through [`Sid`],
//! which admits `[A-Za-z0-9._-]+` and nothing else — so a sid Splunk did
//! not mint cannot smuggle a `/` or a `?` into the path.
//!
//! There is deliberately no arm for anything that writes: no saved-search
//! creation, no index creation, no token minting. A mutating call is not
//! refused at runtime — it is `E0599`, because the arm does not exist.

use std::fmt;

/// A search job id exactly as Splunk minted it, validated before it can
/// be placed in a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid(String);

/// Why a string could not become a [`Sid`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// The candidate contained a byte outside `[A-Za-z0-9._-]`, or was empty.
    #[error("search id {sid:?} is not [A-Za-z0-9._-]+ — refusing to place it in a path")]
    IllegalSid {
        /// The offending candidate, verbatim.
        sid: String,
    },
}

impl Sid {
    fn is_legal_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
    }

    /// The validated id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Sid {
    type Error = RouteError;

    fn try_from(candidate: &str) -> Result<Self, Self::Error> {
        if !candidate.is_empty() && candidate.bytes().all(Self::is_legal_byte) {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(RouteError::IllegalSid {
                sid: candidate.to_owned(),
            })
        }
    }
}

impl TryFrom<String> for Sid {
    type Error = RouteError;

    fn try_from(candidate: String) -> Result<Self, Self::Error> {
        Self::try_from(candidate.as_str())
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The HTTP verb a route is spoken with. Derived from the route, never
/// chosen by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// A read.
    Get,
    /// Login and job creation — the two POSTs an observer needs.
    Post,
    /// Job cleanup. The only DELETE, and it deletes a job holofote created.
    Delete,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        })
    }
}

/// Which results endpoint a server exposes — decided by its version, see
/// [`crate::version::ResultsRoute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultsRoute {
    /// `/services/search/jobs/{sid}/results` — the only route on 8.x;
    /// deprecated and disabled by default from 9.0.1.
    V1,
    /// `/services/search/v2/jobs/{sid}/results` — exists from 9.0; a
    /// `404` on 8.x.
    V2,
}

impl fmt::Display for ResultsRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

/// Every REST route holofote can put a request to. Closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Route {
    /// `POST /services/auth/login` — trade a user + password for a session key.
    Login,
    /// `GET /services/server/info` — version, build, server name.
    ServerInfo,
    /// `GET /services/authentication/current-context` — who the credential is.
    CurrentContext,
    /// `GET /services/data/indexes` — the indexes this role can see.
    Indexes,
    /// `POST /services/search/jobs` — dispatch a search job.
    JobCreate,
    /// `GET /services/search/jobs/{sid}` — the job's dispatch state.
    JobStatus(Sid),
    /// `GET /services/search/jobs/{sid}/results` — results, the 8.x route.
    JobResultsV1(Sid),
    /// `GET /services/search/v2/jobs/{sid}/results` — results, the 9.x route.
    JobResultsV2(Sid),
    /// `DELETE /services/search/jobs/{sid}` — release a job holofote created.
    JobDelete(Sid),
}

/// What a `404` on a route MEANS — a property of the route, so a new arm
/// must say what its absence means before it compiles, and so a 404 on
/// the job-status route is never misread as a version-pairing bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Absence {
    /// The results route was derived from the server version; a 404 says
    /// the derivation was wrong for this host. Report the pairing.
    VersionPairing,
    /// The job the route names no longer exists on the host — reaped by
    /// `auto_cancel` / `timeout`, or lost by a search-head proxy. Re-run.
    JobGone,
    /// A route every Splunk management API serves: the URL is not the
    /// management port, or a proxy in front of it drops the path.
    NotManagementApi,
}

impl Route {
    /// The results route for `sid`, chosen by the server's version.
    #[must_use]
    pub fn job_results(sid: Sid, which: ResultsRoute) -> Self {
        match which {
            ResultsRoute::V1 => Self::JobResultsV1(sid),
            ResultsRoute::V2 => Self::JobResultsV2(sid),
        }
    }

    /// What a `404` on this route means.
    #[must_use]
    pub const fn absence(&self) -> Absence {
        match self {
            Self::JobResultsV1(_) | Self::JobResultsV2(_) => Absence::VersionPairing,
            Self::JobStatus(_) | Self::JobDelete(_) => Absence::JobGone,
            Self::Login
            | Self::ServerInfo
            | Self::CurrentContext
            | Self::Indexes
            | Self::JobCreate => Absence::NotManagementApi,
        }
    }

    /// The verb this route is spoken with.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::Login | Self::JobCreate => Method::Post,
            Self::JobDelete(_) => Method::Delete,
            Self::ServerInfo
            | Self::CurrentContext
            | Self::Indexes
            | Self::JobStatus(_)
            | Self::JobResultsV1(_)
            | Self::JobResultsV2(_) => Method::Get,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login => f.write_str("/services/auth/login"),
            Self::ServerInfo => f.write_str("/services/server/info"),
            Self::CurrentContext => f.write_str("/services/authentication/current-context"),
            Self::Indexes => f.write_str("/services/data/indexes"),
            Self::JobCreate => f.write_str("/services/search/jobs"),
            Self::JobStatus(sid) | Self::JobDelete(sid) => {
                write!(f, "/services/search/jobs/{sid}")
            }
            Self::JobResultsV1(sid) => write!(f, "/services/search/jobs/{sid}/results"),
            Self::JobResultsV2(sid) => write!(f, "/services/search/v2/jobs/{sid}/results"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> Sid {
        Sid::try_from(s).expect("legal sid")
    }

    #[test]
    fn a_sid_admits_only_the_splunk_alphabet() {
        for ok in ["1757400000.123", "scheduler__admin_abc", "a-b_c.d", "X"] {
            assert!(Sid::try_from(ok).is_ok(), "{ok} must be legal");
        }
        for bad in ["", "a/b", "a?x=1", "a b", "../x", "a\n", "é"] {
            assert_eq!(
                Sid::try_from(bad),
                Err(RouteError::IllegalSid {
                    sid: bad.to_owned()
                }),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn every_route_renders_its_documented_path() {
        let s = sid("1757.1");
        let table = [
            (Route::Login, "/services/auth/login"),
            (Route::ServerInfo, "/services/server/info"),
            (
                Route::CurrentContext,
                "/services/authentication/current-context",
            ),
            (Route::Indexes, "/services/data/indexes"),
            (Route::JobCreate, "/services/search/jobs"),
            (Route::JobStatus(s.clone()), "/services/search/jobs/1757.1"),
            (
                Route::JobResultsV1(s.clone()),
                "/services/search/jobs/1757.1/results",
            ),
            (
                Route::JobResultsV2(s.clone()),
                "/services/search/v2/jobs/1757.1/results",
            ),
            (Route::JobDelete(s), "/services/search/jobs/1757.1"),
        ];
        for (route, path) in table {
            assert_eq!(route.to_string(), path);
        }
    }

    #[test]
    fn the_method_is_a_property_of_the_route() {
        let s = sid("x");
        assert_eq!(Route::Login.method(), Method::Post);
        assert_eq!(Route::JobCreate.method(), Method::Post);
        assert_eq!(Route::JobDelete(s.clone()).method(), Method::Delete);
        for read in [
            Route::ServerInfo,
            Route::CurrentContext,
            Route::Indexes,
            Route::JobStatus(s.clone()),
            Route::JobResultsV1(s.clone()),
            Route::JobResultsV2(s),
        ] {
            assert_eq!(read.method(), Method::Get, "{read} is a read");
        }
    }

    #[test]
    fn a_404_means_something_different_on_each_class_of_route() {
        let s = sid("x");
        assert_eq!(
            Route::JobResultsV1(s.clone()).absence(),
            Absence::VersionPairing
        );
        assert_eq!(
            Route::JobResultsV2(s.clone()).absence(),
            Absence::VersionPairing
        );
        assert_eq!(Route::JobStatus(s.clone()).absence(), Absence::JobGone);
        assert_eq!(Route::JobDelete(s).absence(), Absence::JobGone);
        for fixed in [
            Route::Login,
            Route::ServerInfo,
            Route::CurrentContext,
            Route::Indexes,
            Route::JobCreate,
        ] {
            assert_eq!(fixed.absence(), Absence::NotManagementApi, "{fixed}");
        }
    }

    #[test]
    fn job_results_follows_the_version_derived_choice() {
        let s = sid("s");
        assert_eq!(
            Route::job_results(s.clone(), ResultsRoute::V1),
            Route::JobResultsV1(s.clone())
        );
        assert_eq!(
            Route::job_results(s.clone(), ResultsRoute::V2),
            Route::JobResultsV2(s)
        );
    }
}
