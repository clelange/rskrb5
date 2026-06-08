//! Compatibility spike for a future gokrb5-equivalent Rust Kerberos crate.
//!
//! This crate is intentionally not a production Kerberos implementation yet.
//! The first milestone is a decision gate: measure whether existing
//! permissively licensed Rust crates can satisfy the `gokrb5` v8 contract.

#![forbid(unsafe_code)]

#[cfg(feature = "evaluation")]
pub mod evaluation;

pub mod config;
pub mod keytab;

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
}
