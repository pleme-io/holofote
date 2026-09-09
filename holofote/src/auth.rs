//! Credentials: where they come from, how they are held, how they render.
//!
//! Three rules, each a type rather than a convention:
//!
//! * A credential is read from a file, never from argv or the environment,
//!   so a secret never sits in a process listing — and it is read **when it
//!   is needed**, not at startup: the token file on every call, the
//!   user/password files at login and again after a rejected session key.
//!   A rotated token is picked up on the next call; a rotated password on
//!   the next login, which the host forces by rejecting the old session.
//! * Every secret lives in a [`Zeroizing<String>`] from the moment it is
//!   read: the file contents, the rendered `Authorization` value, the
//!   session key. Nothing here implements `Display` for a secret, and the
//!   `Debug` impls redact.
//! * A credential's *shape* is the enum [`Credential`]. The two legal forms
//!   are named once, in [`LEGAL_CREDENTIAL_FORMS`], so a `blind` answer can
//!   quote them instead of describing them.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The two credential forms holofote accepts, spelled as the flags that
/// supply them. Quoted verbatim in refusals and blind answers.
pub const LEGAL_CREDENTIAL_FORMS: [&str; 2] = [
    "--user-file <PATH> --password-file <PATH> (a Splunk user + password, exchanged for a session key)",
    "--token-file <PATH> (a Splunk authentication token, sent as a Bearer)",
];

/// How holofote authenticates — chosen once at startup, read at call time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// `POST /services/auth/login` with the two files' contents; the
    /// resulting session key is sent as `Authorization: Splunk <key>`.
    Password {
        /// File holding the Splunk username.
        user_file: PathBuf,
        /// File holding the password.
        password_file: PathBuf,
    },
    /// `Authorization: Bearer <token>` with the file's contents.
    Token {
        /// File holding the authentication token.
        token_file: PathBuf,
    },
    /// No credential was configured. The server still starts; every tool
    /// answers `blind` naming [`LEGAL_CREDENTIAL_FORMS`].
    None,
}

/// Why a credential could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The file could not be read. The path is named so the remedy is obvious.
    #[error("credential file {path} could not be read: {source}")]
    Unreadable {
        /// The file that was asked for.
        path: PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// The file was readable but held nothing after trimming line endings.
    #[error("credential file {path} is empty")]
    Empty {
        /// The file that was asked for.
        path: PathBuf,
    },
    /// No credential was configured at all.
    #[error("no credential configured; pass one of: {}", LEGAL_CREDENTIAL_FORMS.join(" | "))]
    Absent,
}

/// Read one secret file into zeroizing memory, trimming trailing line
/// endings (a file written by `echo` carries one).
///
/// Only `\n` / `\r` are trimmed, and only at the end: a password with
/// deliberate leading or trailing spaces survives intact.
pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, CredentialError> {
    let raw = std::fs::read_to_string(path).map_err(|source| CredentialError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let mut raw = Zeroizing::new(raw);
    let keep = raw.trim_end_matches(['\n', '\r']).len();
    raw.truncate(keep);
    if raw.is_empty() {
        return Err(CredentialError::Empty {
            path: path.to_path_buf(),
        });
    }
    Ok(raw)
}

/// The `Authorization` scheme Splunk expects for each credential form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `Authorization: Splunk <sessionKey>` — a key from `/services/auth/login`.
    Splunk,
    /// `Authorization: Bearer <token>` — a pre-minted authentication token.
    Bearer,
}

impl Scheme {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Splunk => "Splunk",
            Self::Bearer => "Bearer",
        }
    }
}

/// A rendered `Authorization` header value, held in zeroizing memory.
///
/// Constructed only by [`AuthHeader::render`]; `Debug` prints the scheme and
/// redacts the rest.
#[derive(Clone)]
pub struct AuthHeader {
    scheme: Scheme,
    value: Zeroizing<String>,
}

impl AuthHeader {
    /// `<scheme> <secret>` — the only place a secret meets a header.
    #[must_use]
    pub fn render(scheme: Scheme, secret: &str) -> Self {
        let mut value = Zeroizing::new(String::with_capacity(
            scheme.prefix().len() + 1 + secret.len(),
        ));
        // Writing into a String cannot fail; the Result is the fmt contract.
        let _ = write!(value, "{} {secret}", scheme.prefix());
        Self { scheme, value }
    }

    /// The scheme, for a log line that must not carry the value.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The header value. Borrow it straight into the transport; do not copy
    /// it into anything that is not zeroizing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthHeader({} <redacted>)", self.scheme.prefix())
    }
}

/// A session key as `/services/auth/login` returned it.
#[derive(Clone)]
pub struct SessionKey(Zeroizing<String>);

impl SessionKey {
    /// Wrap a key. Takes ownership so the caller's copy moves rather than
    /// being cloned out of non-zeroizing memory.
    #[must_use]
    pub fn new(key: String) -> Self {
        Self(Zeroizing::new(key))
    }

    /// Render as `Authorization: Splunk <key>`.
    #[must_use]
    pub fn header(&self) -> AuthHeader {
        AuthHeader::render(Scheme::Splunk, &self.0)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn file_with(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn a_trailing_newline_is_trimmed_but_inner_whitespace_is_kept() {
        let f = file_with(b" p4ss word \n");
        assert_eq!(
            read_secret(f.path()).expect("reads").as_str(),
            " p4ss word "
        );
        let crlf = file_with(b"tok\r\n");
        assert_eq!(read_secret(crlf.path()).expect("reads").as_str(), "tok");
        let bare = file_with(b"tok");
        assert_eq!(read_secret(bare.path()).expect("reads").as_str(), "tok");
    }

    #[test]
    fn an_empty_or_missing_file_is_a_typed_error_naming_the_path() {
        let empty = file_with(b"\n");
        let err = read_secret(empty.path()).expect_err("empty");
        assert!(matches!(err, CredentialError::Empty { .. }));
        assert!(
            err.to_string()
                .contains(&empty.path().display().to_string())
        );

        let missing = Path::new("/definitely/not/here/holofote-secret");
        let err = read_secret(missing).expect_err("missing");
        assert!(matches!(err, CredentialError::Unreadable { .. }));
        assert!(
            err.to_string()
                .contains("/definitely/not/here/holofote-secret")
        );
    }

    #[test]
    fn the_header_renders_each_scheme_and_debug_redacts() {
        let splunk = AuthHeader::render(Scheme::Splunk, "k3y");
        assert_eq!(splunk.as_str(), "Splunk k3y");
        let bearer = AuthHeader::render(Scheme::Bearer, "t0k");
        assert_eq!(bearer.as_str(), "Bearer t0k");
        let shown = format!("{splunk:?} {bearer:?}");
        assert!(!shown.contains("k3y") && !shown.contains("t0k"), "{shown}");
        assert!(shown.contains("Splunk") && shown.contains("Bearer"));
        assert!(!format!("{:?}", SessionKey::new("s3".into())).contains("s3"));
    }

    #[test]
    fn a_session_key_renders_as_the_splunk_scheme() {
        assert_eq!(
            SessionKey::new("abc".into()).header().as_str(),
            "Splunk abc"
        );
        assert_eq!(
            SessionKey::new("abc".into()).header().scheme(),
            Scheme::Splunk
        );
    }

    #[test]
    fn the_absent_credential_names_both_legal_forms() {
        let msg = CredentialError::Absent.to_string();
        for form in LEGAL_CREDENTIAL_FORMS {
            assert!(msg.contains(form), "{msg}");
        }
    }
}
