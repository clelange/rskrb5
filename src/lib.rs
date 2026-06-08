//! Compatibility spike for a future gokrb5-equivalent Rust Kerberos crate.
//!
//! This crate is intentionally not a production Kerberos implementation yet.
//! The first milestone is a decision gate: measure whether existing
//! permissively licensed Rust crates can satisfy the `gokrb5` v8 contract.

#![forbid(unsafe_code)]

#[cfg(feature = "evaluation")]
pub mod evaluation;

pub mod ccache;
#[cfg(feature = "messages")]
pub mod client;
pub mod config;
pub mod crypto;
mod der;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "messages")]
pub mod kadmin;
pub mod keytab;
pub mod pac;
#[cfg(feature = "messages")]
pub mod service;
#[cfg(feature = "spnego")]
pub mod spnego;

/// Current crate-level result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the compatibility spike utilities.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Hex fixture data failed to decode.
    #[cfg(feature = "evaluation")]
    #[error("fixture hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A candidate ASN.1/DER decoder failed.
    #[error("candidate decode failed: {0}")]
    Decode(String),

    /// Keytab parsing or serialization failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] keytab::Error),

    /// krb5.conf parsing failed.
    #[error("config error: {0}")]
    Config(#[from] config::Error),

    /// Credential cache parsing or serialization failed.
    #[error("ccache error: {0}")]
    CCache(#[from] ccache::Error),

    /// Kerberos cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),

    /// PAC parsing or verification failed.
    #[error("PAC error: {0}")]
    Pac(#[from] pac::Error),

    /// AS exchange client processing failed.
    #[cfg(feature = "messages")]
    #[error("client error: {0}")]
    Client(#[from] client::Error),

    /// AP-REQ service validation failed.
    #[cfg(feature = "messages")]
    #[error("service validation error: {0}")]
    Service(#[from] service::Error),

    /// SPNEGO/GSSAPI token processing failed.
    #[cfg(feature = "spnego")]
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] spnego::Error),
}
