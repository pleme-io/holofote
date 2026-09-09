//! The per-host TLS posture — a typed choice, never a boolean.
//!
//! Splunk ships a stock self-signed certificate (`CN=SplunkServerDefaultCert`)
//! that no public root signs, so `system` verification fails against an
//! untouched install. That is a fact about the world and it is typed here
//! as three postures rather than dissolved into `verify: false`. `AcceptAny`
//! is a **degraded** posture and says so ([`TlsPosture::is_degraded`]) so a
//! server can log it once at startup and name it in every `whoami`.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// How the transport verifies the host's certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum TlsPosture {
    /// Verify against the compiled-in public web-PKI roots (the default).
    ///
    /// "System" names the intent — trust what the platform trusts — while
    /// the implementation is `webpki-roots`, a pure-Rust bundle, because
    /// reading the OS keychain would link a C framework for no gain.
    #[default]
    System,
    /// Accept any certificate and any hostname. Degraded; logged as such.
    AcceptAny,
    /// Add one private root (a PEM file) to the trusted set.
    Ca(PathBuf),
}

/// Why a `--tls` value was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsPostureError {
    /// Not one of the three spellings.
    #[error("unknown TLS posture {got:?}; legal: system | accept-any | ca:<PEM_PATH>")]
    Unknown {
        /// What was passed.
        got: String,
    },
    /// `ca:` with nothing after it.
    #[error("`ca:` needs a PEM path after the colon")]
    EmptyCaPath,
}

impl TlsPosture {
    /// The three legal spellings, for a refusal's `legal` set.
    pub const LEGAL: [&'static str; 3] = ["system", "accept-any", "ca:<PEM_PATH>"];

    /// Whether this posture skips verification — the one an operator must
    /// be told about.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self, Self::AcceptAny)
    }
}

impl FromStr for TlsPosture {
    type Err = TlsPostureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "system" => Ok(Self::System),
            "accept-any" => Ok(Self::AcceptAny),
            other => match other.strip_prefix("ca:") {
                Some("") => Err(TlsPostureError::EmptyCaPath),
                Some(path) => Ok(Self::Ca(PathBuf::from(path))),
                None => Err(TlsPostureError::Unknown {
                    got: other.to_owned(),
                }),
            },
        }
    }
}

impl fmt::Display for TlsPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => f.write_str("system"),
            Self::AcceptAny => f.write_str("accept-any"),
            Self::Ca(path) => write!(f, "ca:{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_spellings_round_trip() {
        for (text, posture) in [
            ("system", TlsPosture::System),
            ("accept-any", TlsPosture::AcceptAny),
            (
                "ca:/etc/ssl/private-root.pem",
                TlsPosture::Ca(PathBuf::from("/etc/ssl/private-root.pem")),
            ),
        ] {
            let parsed: TlsPosture = text.parse().expect("parses");
            assert_eq!(parsed, posture);
            assert_eq!(parsed.to_string(), text);
        }
    }

    #[test]
    fn anything_else_is_refused_naming_the_legal_set() {
        let err = "insecure".parse::<TlsPosture>().expect_err("refused");
        assert_eq!(
            err,
            TlsPostureError::Unknown {
                got: "insecure".into()
            }
        );
        assert!(err.to_string().contains("accept-any"));
        assert_eq!(
            "ca:".parse::<TlsPosture>(),
            Err(TlsPostureError::EmptyCaPath)
        );
        assert_eq!(
            "System".parse::<TlsPosture>(),
            Err(TlsPostureError::Unknown {
                got: "System".into()
            })
        );
    }

    #[test]
    fn only_accept_any_is_degraded() {
        assert!(TlsPosture::AcceptAny.is_degraded());
        assert!(!TlsPosture::System.is_degraded());
        assert!(!TlsPosture::Ca(PathBuf::from("x.pem")).is_degraded());
        assert_eq!(TlsPosture::default(), TlsPosture::System);
    }
}
