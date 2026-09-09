//! The server version, read once, and the one decision derived from it.
//!
//! Splunk moved the results endpoint: `/services/search/v2/jobs/{sid}/results`
//! exists from 9.0 and is a `404` before it; the v1 route is the only one on
//! 8.x and is deprecated — disabled by default — from 9.0.1 (Cloud 9.0.2208).
//! Measured against a Splunk Enterprise 8.2.2.1 install: the v2 route
//! returns `404`. So the route is not configured and not guessed; it is
//! **derived** from `GET /services/server/info`'s `version` field, and a
//! version that does not parse is a typed error rather than a default.

use std::fmt;

pub use crate::route::ResultsRoute;

/// A Splunk server version, e.g. `8.2.2.1` or `9.0.1`.
///
/// Only `major.minor` participate in any decision; the remaining components
/// are kept for display.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerVersion {
    major: u32,
    minor: u32,
    raw: String,
}

/// Why a version string could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// Not `N.N[.N…]` with every component a decimal integer.
    #[error("server version {raw:?} is not of the form MAJOR.MINOR[.PATCH…]")]
    Unparseable {
        /// The offending string, verbatim.
        raw: String,
    },
}

impl ServerVersion {
    /// The first dotted component.
    #[must_use]
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// The second dotted component.
    #[must_use]
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// Which results route this version serves.
    ///
    /// `>= 9.0` → v2; anything older → v1. Comparing `major.minor` rather
    /// than `major` alone keeps the rule legible against the vendor's own
    /// statement of it, even though the two agree today.
    #[must_use]
    pub const fn results_route(&self) -> ResultsRoute {
        const BOUNDARY: (u32, u32) = (9, 0);
        let (major, minor) = (self.major, self.minor);
        if major > BOUNDARY.0 || (major == BOUNDARY.0 && minor >= BOUNDARY.1) {
            ResultsRoute::V2
        } else {
            ResultsRoute::V1
        }
    }
}

impl TryFrom<&str> for ServerVersion {
    type Error = VersionError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let unparseable = || VersionError::Unparseable {
            raw: raw.to_owned(),
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(unparseable());
        }
        let mut parts = trimmed.split('.');
        let major = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(unparseable)?;
        let minor = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(unparseable)?;
        // Every remaining component must still be numeric — `9.0.1-beta`
        // is refused rather than read as 9.0.
        if parts.any(|p| p.parse::<u32>().is_err()) {
            return Err(unparseable());
        }
        Ok(Self {
            major,
            minor,
            raw: trimmed.to_owned(),
        })
    }
}

impl fmt::Display for ServerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> ServerVersion {
        ServerVersion::try_from(s).expect("parses")
    }

    /// The table the module exists for. `8.2.2.1` is the version the 404
    /// was measured on; the rest are the vendor's stated boundary and one
    /// beyond it.
    #[test]
    fn the_results_route_is_derived_from_the_version() {
        assert_eq!(v("8.2.2.1").results_route(), ResultsRoute::V1);
        assert_eq!(v("8.9.99").results_route(), ResultsRoute::V1);
        assert_eq!(v("9.0.0").results_route(), ResultsRoute::V2);
        assert_eq!(v("9.0.1").results_route(), ResultsRoute::V2);
        assert_eq!(v("9.4.2").results_route(), ResultsRoute::V2);
        assert_eq!(v("10.4.0").results_route(), ResultsRoute::V2);
    }

    #[test]
    fn garbage_is_a_typed_error_not_a_default_route() {
        for bad in ["", "eight", "9", "9.x", "9.0.1-beta", "v9.0", "9..1", " . "] {
            assert_eq!(
                ServerVersion::try_from(bad),
                Err(VersionError::Unparseable {
                    raw: bad.to_owned()
                }),
                "{bad:?} must not parse"
            );
        }
    }

    #[test]
    fn components_and_display_are_preserved() {
        let ver = v(" 8.2.2.1 ");
        assert_eq!(ver.major(), 8);
        assert_eq!(ver.minor(), 2);
        assert_eq!(ver.to_string(), "8.2.2.1");
    }
}
