//! Pure-Rust Kerberos v5 client/service library.
//!
//! The `0.1.x` line exposes a narrow, client-oriented preview surface for
//! projects that need Kerberos password or keytab login, FILE/WRFILE/DIR
//! credential-cache loading, and HTTP Negotiate/SPNEGO header generation.
//! Broader `gokrb5` parity work continues behind the same lower-level modules.
//!
//! ```ignore
//! let config = rskrb5::Config::load_default()?;
//! let mut client =
//!     rskrb5::NegotiateClient::from_ccache_name(config, "FILE:/tmp/krb5cc")?;
//! let header = client
//!     .authorization_header_for_host("HTTP", "auth.cern.ch")
//!     .await?;
//! ```
//!
//! # Feature Flags
//!
//! - `messages`: Kerberos ASN.1 message wrappers and protocol modules.
//! - `spnego`: SPNEGO/GSSAPI token and HTTP Negotiate header support.
//! - `tokio`: async KDC/kpasswd transports and high-level client flows.
//! - `http`: generic `http` crate request/response helpers.
//! - `tower`: service-side Tower Negotiate middleware.
//! - `serde`: JSON diagnostics and redacted metadata helpers.
//! - `evaluation`: candidate-crate compatibility report generation.
//!
//! # Current Limits
//!
//! Platform credential stores (`API`, `KCM`, `KEYRING`, `MSLSA`), FAST,
//! PKINIT, system GSSAPI/SSPI facades, and full maintained Active Directory
//! CI are outside the supported `0.1.x` preview scope. Unsupported credential
//! cache stores are reported as
//! [`ccache::Error::UnsupportedCacheType`].

#![forbid(unsafe_code)]

#[cfg(feature = "evaluation")]
pub mod evaluation;

pub mod ccache;
#[cfg(feature = "messages")]
pub mod client;
pub mod config;
pub mod crypto;
#[cfg(feature = "messages")]
mod der;
mod file_name;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "messages")]
pub mod kadmin;
pub mod keytab;
#[cfg(feature = "messages")]
pub mod krb_cred;
#[cfg(feature = "messages")]
pub mod messages;
pub mod pac;
#[cfg(feature = "messages")]
pub mod service;
#[cfg(feature = "spnego")]
pub mod spnego;

#[cfg(feature = "messages")]
pub use client::Principal;
#[cfg(all(feature = "tokio", feature = "spnego"))]
pub use client::{BlockingNegotiateClient, NegotiateClient};
pub use config::Config;

/// Current crate-level result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-level error type.
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

    /// kadmin message processing failed.
    #[cfg(feature = "messages")]
    #[error("kadmin error: {0}")]
    Kadmin(#[from] kadmin::Error),

    /// KRB-CRED processing failed.
    #[cfg(feature = "messages")]
    #[error("KRB-CRED error: {0}")]
    KrbCred(#[from] krb_cred::Error),

    /// AP-REQ service validation failed.
    #[cfg(feature = "messages")]
    #[error("service validation error: {0}")]
    Service(#[from] service::Error),

    /// SPNEGO/GSSAPI token processing failed.
    #[cfg(feature = "spnego")]
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] spnego::Error),
}
