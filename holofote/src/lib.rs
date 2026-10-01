//! holofote (holofote, *searchlight*) — a typed Splunk REST client whose
//! every answer says which of four things happened.
//!
//! # What it is
//!
//! An **observe-only** client over Splunk's management API (port 8089):
//! who am I, which indexes can I see, run one bounded search. Three
//! questions, and the type system is arranged so a fourth kind — a write —
//! has nowhere to go: [`route::Route`] is a closed enum with no mutating arm,
//! so a call that would change Splunk state is `E0599`, not a runtime
//! refusal.
//!
//! # The shape
//!
//! | module | owns |
//! |---|---|
//! | [`transport`] | the seam: one trait, the `reqwest` impl, the scripted mock (feature `mock`) |
//! | [`route`] | the closed route enum, its one `Display`, the validated `Sid` |
//! | [`auth`] | credential files read at call time into zeroizing memory; the header renderer |
//! | [`version`] | the server version, and the v1/v2 results route derived from it |
//! | [`spl`] | typed SPL — identifiers with one grammar, time specs, a bounded cap, ONE renderer |
//! | [`config`] | `HolofoteConfig`: shikumi tiers + a `(defholofote …)` face on one struct |
//! | [`outcome`] | `Outcome` (found / empty / refused / blind) and the typed causes behind the last two |
//! | [`client`] | `SplunkClient<T: Transport>`: login, the single re-login, the job lifecycle |
//! | [`targets`] | `Targets<T>`: several clients keyed by label; an unknown target is a `Refusal` naming the legal ones |
//!
//! # Four outcomes, never collapsed
//!
//! The reader of these answers is a language model with no peripheral
//! vision. So an empty index is `empty` (a finding), a bad time spec is
//! `refused` (retry differently — the legal forms are listed), and a host
//! behind a VPN that is down is `blind` (nobody knows — conclude nothing).
//! Every HTTP status is classified by [`handan::judge`]; nothing here
//! re-derives what a `403` means.
//!
//! # Typed emission
//!
//! There is no `format!` macro call — nor its hand-expansion — outside the
//! test modules of this crate. Every string an agent reads is a `thiserror`
//! message, a `Display` impl, a `tracing` event, or serde output — and
//! `tests/no_estate_identifiers.rs` keeps it that way.

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod config;
pub mod outcome;
pub mod route;
pub mod spl;
pub mod targets;
pub mod tls;
pub mod transport;
pub mod version;

pub use auth::{Credential, LEGAL_CREDENTIAL_FORMS};
pub use client::{Identity, IndexList, IndexSummary, SearchHits, SplunkClient, WhoAmI};
pub use config::{ConfigError, HolofoteConfig};
pub use outcome::Outcome;
pub use route::{ResultsRoute, Route, Sid};
pub use spl::{Search, SearchRequest, SortRequest, TermRequest};
pub use targets::{Targets, TargetsError};
pub use tls::TlsPosture;
#[cfg(any(test, feature = "mock"))]
pub use transport::MockTransport;
pub use transport::{ConnectEvidence, ReqwestTransport, Transport};
pub use version::ServerVersion;
