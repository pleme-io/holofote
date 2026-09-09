//! `HolofoteConfig` — the ONE typed bounds surface, carrying both faces.
//!
//! shikumi's tiers (`bare` / `prescribed` / a YAML overlay) and the
//! tatara-lisp `(defholofote …)` form are two faces of one struct, on the
//! escriba/banken precedent. Every field is a **bound** the server enforces
//! against one Splunk host; nothing here identifies a host, a tenant, or a
//! credential — those are argv, and they are per host.
//!
//! The YAML face carries `deny_unknown_fields`, so an operator's typo is a
//! loud failure (parse-time-rejected). A **partial** overlay is legal and
//! folds onto the prescribed tier: `#[serde(default)]` on the struct routes
//! every omitted key through `Default`, which delegates to
//! `prescribed_default()` — one source, no per-field default functions to
//! drift.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tatara_lisp::DeriveTataraDomain;

/// The canonical authored form that ships with the crate.
pub const CANONICAL_HOLOFOTE_LISP: &str = include_str!("../specs/holofote.lisp");

/// The bounds holofote enforces against one Splunk host.
#[derive(DeriveTataraDomain, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[tatara(keyword = "defholofote")]
pub struct HolofoteConfig {
    /// The hard cap on any search's `limit`; also sent as `max_count` and as
    /// the results `count`. A request above it is refused, never clamped.
    ///
    /// Lisp face: `:max-results 1000`.
    pub max_results: u32,

    /// How many indexes are listed when the caller names no limit.
    ///
    /// Lisp face: `:default-indexes-limit 100`.
    pub default_indexes_limit: u32,

    /// How often a running job is polled, in milliseconds.
    ///
    /// Lisp face: `:poll-interval-ms 500`.
    pub poll_interval_ms: u64,

    /// The wall-clock bound on one search, holofote-side; also sent as
    /// Splunk's `max_time`.
    ///
    /// Lisp face: `:max-search-seconds 60`.
    pub max_search_seconds: u64,

    /// Sent as Splunk's `timeout`: how long a finished job's artifacts are
    /// kept. A backstop — holofote deletes its own jobs.
    ///
    /// Lisp face: `:job-ttl-seconds 300`.
    pub job_ttl_seconds: u64,

    /// Sent as Splunk's `auto_cancel`: idle seconds before an unpolled job
    /// is cancelled server-side.
    ///
    /// Lisp face: `:job-auto-cancel-seconds 120`.
    pub job_auto_cancel_seconds: u64,

    /// TCP connect + TLS handshake budget, in milliseconds.
    ///
    /// Lisp face: `:connect-timeout-ms 5000`.
    pub connect_timeout_ms: u64,

    /// Whole-request budget for one REST call, in milliseconds.
    ///
    /// Lisp face: `:request-timeout-ms 30000`.
    pub request_timeout_ms: u64,

    /// How many terms one search may carry. A request over it is refused.
    ///
    /// Lisp face: `:max-terms 32`.
    pub max_terms: u32,

    /// How many bytes one term value may carry. Identifiers are bounded by
    /// their grammar; this bounds the one free-form string a caller can
    /// put in a search, so a value is never a payload.
    ///
    /// Lisp face: `:max-term-bytes 4096`.
    pub max_term_bytes: u32,

    /// How many names each of `fields` and `stats_count_by` may carry.
    ///
    /// Lisp face: `:max-fields 32`.
    pub max_fields: u32,
}

/// Why a config was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The overlay file could not be read.
    #[error("config overlay {path} could not be read: {source}")]
    Unreadable {
        /// The path given.
        path: std::path::PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// The overlay file did not parse — including an unknown key.
    #[error("config overlay {path} is not a valid HolofoteConfig: {source}")]
    Malformed {
        /// The path given.
        path: std::path::PathBuf,
        /// `serde_yaml`'s reason, which names the offending key.
        #[source]
        source: serde_yaml::Error,
    },
    /// A bound that would make every request illegal or every call hang.
    #[error("config field {field} must be at least 1 (got 0)")]
    ZeroBound {
        /// The camelCase field name.
        field: &'static str,
    },
}

impl HolofoteConfig {
    /// Refuse bounds that would make the server useless: a zero cap makes
    /// every limit illegal, a zero poll interval spins, a zero timeout
    /// fails every call before it starts.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let checks: [(&'static str, u64); 9] = [
            ("maxResults", u64::from(self.max_results)),
            ("defaultIndexesLimit", u64::from(self.default_indexes_limit)),
            ("pollIntervalMs", self.poll_interval_ms),
            ("maxSearchSeconds", self.max_search_seconds),
            ("connectTimeoutMs", self.connect_timeout_ms),
            ("requestTimeoutMs", self.request_timeout_ms),
            ("maxTerms", u64::from(self.max_terms)),
            ("maxTermBytes", u64::from(self.max_term_bytes)),
            ("maxFields", u64::from(self.max_fields)),
        ];
        checks
            .iter()
            .find(|(_, v)| *v == 0)
            .map_or(Ok(()), |(field, _)| Err(ConfigError::ZeroBound { field }))
    }

    /// Read a YAML overlay **strictly** and fold it onto the prescribed tier.
    ///
    /// Strict where `shikumi::TieredConfig::resolve_tier` is lenient: that
    /// method falls back to `prescribed_default()` when the file is missing
    /// or malformed, with a warning. For a bounds file that would mean an
    /// operator's `maxResults: 10` silently becoming `1000`, so a server
    /// starting from a file refuses to start on a file it cannot honour.
    pub fn from_overlay_file(path: &Path) -> Result<Self, ConfigError> {
        use shikumi::TieredConfig as _;
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let overlay: Self =
            serde_yaml::from_str(&text).map_err(|source| ConfigError::Malformed {
                path: path.to_path_buf(),
                source,
            })?;
        let folded = overlay.extend(&Self::prescribed_default());
        folded.validate()?;
        Ok(folded)
    }

    /// Compile a `(defholofote …)` form — the Lisp authoring face.
    pub fn from_lisp(src: &str) -> Result<Self, tatara_lisp::LispError> {
        use tatara_lisp::domain::TataraDomain as _;
        let forms = tatara_lisp::read(src)?;
        let first = forms
            .first()
            .ok_or_else(|| tatara_lisp::LispError::Compile {
                form: "defholofote".into(),
                message: "empty config — expected one top-level (defholofote …) form".into(),
            })?;
        Self::compile_from_sexp(first)
    }

    /// The poll cadence as a `Duration`.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    /// The holofote-side search bound as a `Duration`.
    #[must_use]
    pub const fn max_search(&self) -> Duration {
        Duration::from_secs(self.max_search_seconds)
    }

    /// The transport deadlines.
    #[must_use]
    pub const fn timeouts(&self) -> crate::transport::Timeouts {
        crate::transport::Timeouts {
            connect: Duration::from_millis(self.connect_timeout_ms),
            request: Duration::from_millis(self.request_timeout_ms),
        }
    }

    /// The bounds one search is validated against.
    #[must_use]
    pub const fn search_bounds(&self) -> crate::spl::SearchBounds {
        crate::spl::SearchBounds {
            max_results: self.max_results,
            max_terms: self.max_terms,
            max_term_bytes: self.max_term_bytes,
            max_fields: self.max_fields,
        }
    }
}

impl shikumi::TieredConfig for HolofoteConfig {
    /// Tier 0 — the zero-opinion floor: the tightest bounds under which one
    /// search can still complete. One result, one index, a slow poll, short
    /// deadlines.
    fn bare() -> Self {
        Self {
            max_results: 1,
            default_indexes_limit: 1,
            poll_interval_ms: 1_000,
            max_search_seconds: 10,
            job_ttl_seconds: 60,
            job_auto_cancel_seconds: 30,
            connect_timeout_ms: 1_000,
            request_timeout_ms: 5_000,
            max_terms: 1,
            max_term_bytes: 64,
            max_fields: 1,
        }
    }

    /// Tier 2 — what the server boots with. Mirrors `specs/holofote.lisp`;
    /// `prescribed_mirrors_the_authored_lisp` pins the two together.
    fn prescribed_default() -> Self {
        Self {
            max_results: 1_000,
            default_indexes_limit: 100,
            poll_interval_ms: 500,
            max_search_seconds: 60,
            job_ttl_seconds: 300,
            job_auto_cancel_seconds: 120,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
            max_terms: 32,
            max_term_bytes: 4_096,
            max_fields: 32,
        }
    }
}

impl Default for HolofoteConfig {
    /// Delegates to the prescribed tier — and, through `#[serde(default)]`,
    /// is what an omitted overlay key resolves to.
    fn default() -> Self {
        <Self as shikumi::TieredConfig>::prescribed_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikumi::{ConfigTier, TieredConfig};
    use std::io::Write as _;

    #[test]
    fn bare_is_below_prescribed_on_every_bound() {
        let b = HolofoteConfig::bare();
        let p = HolofoteConfig::prescribed_default();
        assert_eq!(b.max_results, 1);
        assert!(b.max_results < p.max_results);
        assert!(b.default_indexes_limit < p.default_indexes_limit);
        assert!(b.max_search_seconds < p.max_search_seconds);
        assert!(b.connect_timeout_ms < p.connect_timeout_ms);
        assert!(b.request_timeout_ms < p.request_timeout_ms);
        assert!(b.max_terms < p.max_terms);
        assert!(b.max_term_bytes < p.max_term_bytes);
        assert!(b.max_fields < p.max_fields);
        assert!(b.validate().is_ok(), "the floor must still be usable");
        assert!(p.validate().is_ok());
        assert_eq!(HolofoteConfig::default(), p);
        assert_eq!(HolofoteConfig::resolve_tier(ConfigTier::Bare), b);
        assert_eq!(HolofoteConfig::resolve_tier(ConfigTier::Default), p);
    }

    /// THE GATE: a valid document plus ONE unknown key is refused, and the
    /// error names the key.
    #[test]
    fn an_unknown_yaml_key_is_rejected_by_name() {
        let bad = "maxResults: 50\npollIntervalMs: 250\nmaxResultz: 10\n";
        let good = bad.replace("maxResultz: 10\n", "");
        serde_yaml::from_str::<HolofoteConfig>(&good)
            .expect("the same document without the key is valid");
        let err = serde_yaml::from_str::<HolofoteConfig>(bad).expect_err("unknown key");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains("maxResultz"),
            "{msg}"
        );
    }

    /// A PARTIAL overlay folds onto prescribed: the two keys given win, the
    /// nine omitted keep their prescribed values (not bare, not zero).
    #[test]
    fn a_partial_custom_overlay_folds_onto_prescribed() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"maxResults: 50\nconnectTimeoutMs: 1500\n")
            .expect("write");

        let via_shikumi = HolofoteConfig::resolve_tier(ConfigTier::Custom(f.path().to_path_buf()));
        let via_strict = HolofoteConfig::from_overlay_file(f.path()).expect("strict load");
        assert_eq!(via_shikumi, via_strict, "both faces fold the same way");

        let p = HolofoteConfig::prescribed_default();
        assert_eq!(via_strict.max_results, 50);
        assert_eq!(via_strict.connect_timeout_ms, 1_500);
        assert_eq!(via_strict.default_indexes_limit, p.default_indexes_limit);
        assert_eq!(via_strict.poll_interval_ms, p.poll_interval_ms);
        assert_eq!(via_strict.max_search_seconds, p.max_search_seconds);
        assert_eq!(via_strict.job_ttl_seconds, p.job_ttl_seconds);
        assert_eq!(
            via_strict.job_auto_cancel_seconds,
            p.job_auto_cancel_seconds
        );
        assert_eq!(via_strict.request_timeout_ms, p.request_timeout_ms);
        assert_eq!(via_strict.max_terms, p.max_terms);
        assert_eq!(via_strict.max_term_bytes, p.max_term_bytes);
        assert_eq!(via_strict.max_fields, p.max_fields);
    }

    /// Where the two faces DIFFER, by design: shikumi falls back silently on
    /// a malformed file; the strict loader refuses and names the key.
    #[test]
    fn the_strict_loader_refuses_what_shikumi_would_paper_over() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"maxResults: 50\nbogusKey: 1\n")
            .expect("write");
        assert_eq!(
            HolofoteConfig::resolve_tier(ConfigTier::Custom(f.path().to_path_buf())),
            HolofoteConfig::prescribed_default(),
            "shikumi's contract: fall back"
        );
        let err = HolofoteConfig::from_overlay_file(f.path()).expect_err("strict refuses");
        assert!(matches!(err, ConfigError::Malformed { .. }));
        assert!(err.to_string().contains("bogusKey"), "{err}");

        let missing = HolofoteConfig::from_overlay_file(Path::new("/nope/holofote.yaml"))
            .expect_err("missing");
        assert!(matches!(missing, ConfigError::Unreadable { .. }));
    }

    #[test]
    fn a_zero_bound_is_refused_by_field_name() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"maxResults: 0\n").expect("write");
        let err = HolofoteConfig::from_overlay_file(f.path()).expect_err("zero cap");
        assert!(
            matches!(
                err,
                ConfigError::ZeroBound {
                    field: "maxResults"
                }
            ),
            "{err:?}"
        );
        let c = HolofoteConfig {
            poll_interval_ms: 0,
            ..HolofoteConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ConfigError::ZeroBound {
                field: "pollIntervalMs"
            })
        ));
        // A zero search bound would refuse every request; refused by name.
        let c = HolofoteConfig {
            max_term_bytes: 0,
            ..HolofoteConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ConfigError::ZeroBound {
                field: "maxTermBytes"
            })
        ));
        // Zero is legal for the two Splunk-side backstops: 0 means "never".
        let c = HolofoteConfig {
            job_ttl_seconds: 0,
            job_auto_cancel_seconds: 0,
            ..HolofoteConfig::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn yaml_round_trips_in_camel_case() {
        let p = HolofoteConfig::default();
        let yaml = serde_yaml::to_string(&p).expect("serialize");
        assert!(
            yaml.contains("maxResults") && yaml.contains("jobAutoCancelSeconds"),
            "{yaml}"
        );
        let back: HolofoteConfig = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(back, p);
    }

    #[test]
    fn prescribed_mirrors_the_authored_lisp() {
        let authored =
            HolofoteConfig::from_lisp(CANONICAL_HOLOFOTE_LISP).expect("the shipped form compiles");
        assert_eq!(
            authored,
            HolofoteConfig::prescribed_default(),
            "specs/holofote.lisp drifted from prescribed_default() — the two faces must agree"
        );
    }

    #[test]
    fn the_lisp_face_refuses_a_missing_kwarg_and_an_empty_source() {
        let err =
            HolofoteConfig::from_lisp("(defholofote :max-results 10)").expect_err("incomplete");
        assert!(err.to_string().contains("default-indexes-limit"), "{err}");
        assert!(HolofoteConfig::from_lisp("").is_err());
        assert!(HolofoteConfig::from_lisp("(defsomethingelse :max-results 10)").is_err());
    }

    #[test]
    fn durations_and_search_bounds_derive_from_the_fields() {
        let c = HolofoteConfig::default();
        assert_eq!(c.poll_interval(), Duration::from_millis(500));
        assert_eq!(c.max_search(), Duration::from_secs(60));
        assert_eq!(c.timeouts().connect, Duration::from_secs(5));
        assert_eq!(c.timeouts().request, Duration::from_secs(30));
        let b = c.search_bounds();
        assert_eq!(b.max_results, c.max_results);
        assert_eq!(b.max_terms, c.max_terms);
        assert_eq!(b.max_term_bytes, c.max_term_bytes);
        assert_eq!(b.max_fields, c.max_fields);
    }
}
