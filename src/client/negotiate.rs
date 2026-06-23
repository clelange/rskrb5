use std::fmt;

use crate::config::Config;
use crate::keytab::Keytab;

use super::{Error, KdcProtocol, KpasswdRequestOptions, Principal, TokioClient};

/// Small client API for HTTP Negotiate/SPNEGO initiator headers.
///
/// This wrapper keeps the stable HTTP-Negotiate surface narrow while reusing
/// [`TokioClient`] for ticket acquisition, cache reuse, and SPNEGO token
/// construction. Advanced Kerberos flows remain available on `TokioClient`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateClient {
    inner: TokioClient,
}

impl NegotiateClient {
    /// Wrap an existing high-level Tokio client.
    pub fn from_tokio_client(client: TokioClient) -> Self {
        Self { inner: client }
    }

    /// Create a password-backed Negotiate client using automatic UDP/TCP KDC transport.
    pub fn with_password(config: Config, client: Principal, password: impl Into<Vec<u8>>) -> Self {
        Self::from_tokio_client(TokioClient::with_password(
            config,
            KdcProtocol::Auto,
            client,
            password,
        ))
    }

    /// Create a keytab-backed Negotiate client using automatic UDP/TCP KDC transport.
    pub fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self {
        Self::from_tokio_client(TokioClient::with_keytab(
            config,
            KdcProtocol::Auto,
            client,
            keytab,
        ))
    }

    /// Create a keytab-backed Negotiate client by loading a file-backed keytab name.
    pub fn with_keytab_name(
        config: Config,
        client: Principal,
        keytab_name: impl AsRef<str>,
    ) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::with_keytab_name(
            config,
            KdcProtocol::Auto,
            client,
            keytab_name,
        )?))
    }

    /// Create a cache-only Negotiate client by loading a ccache name.
    pub fn from_ccache_name(config: Config, cache_name: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::from_ccache_name(
            config,
            KdcProtocol::Auto,
            cache_name,
        )?))
    }

    /// Create a cache-only Negotiate client from the default credential cache.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::from_default_ccache(
            config,
            KdcProtocol::Auto,
        )?))
    }

    /// Create a cache-only Negotiate client by loading the cache named by `KRB5CCNAME`.
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::from_ccache_env(
            config,
            KdcProtocol::Auto,
        )?))
    }

    /// Borrow the wrapped `TokioClient`.
    pub fn inner(&self) -> &TokioClient {
        &self.inner
    }

    /// Mutably borrow the wrapped `TokioClient`.
    pub fn inner_mut(&mut self) -> &mut TokioClient {
        &mut self.inner
    }

    /// Consume this wrapper and return the wrapped `TokioClient`.
    pub fn into_inner(self) -> TokioClient {
        self.inner
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    pub async fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.authorization_context(service).await?.header)
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    ///
    /// The service realm is left empty so `TokioClient` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    pub async fn authorization_header_for_host(
        &mut self,
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<String, Error> {
        Ok(self
            .authorization_context_for_host(service, host)
            .await?
            .header)
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    pub async fn authorization_context(
        &mut self,
        service: Principal,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.inner.spnego_context(service).await
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    pub async fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: crate::spnego::InitiatorContextOptions,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.inner
            .spnego_context_with_options(service, options)
            .await
    }

    /// Build a SPNEGO initiator context for a host-based service.
    ///
    /// The service realm is left empty so `TokioClient` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    pub async fn authorization_context_for_host(
        &mut self,
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.authorization_context(Principal::host_based_service(service, host)?)
            .await
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    pub async fn change_password(
        &mut self,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.inner
            .change_password(new_password, sender_address)
            .await
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    pub async fn change_password_for(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.inner
            .change_password_for(target, new_password, sender_address)
            .await
    }

    /// Change this client's password using explicit kpasswd request metadata.
    pub async fn change_password_with_options(
        &mut self,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.inner
            .change_password_with_options(new_password, options)
            .await
    }

    /// Change the given target principal's password using explicit kpasswd
    /// request metadata.
    pub async fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.inner
            .change_password_for_with_options(target, new_password, options)
            .await
    }
}

/// Blocking wrapper for synchronous CLI consumers of HTTP Negotiate.
///
/// Async applications should use [`NegotiateClient`] directly. This type owns a
/// small current-thread Tokio runtime so callers can generate headers without
/// managing a runtime.
pub struct BlockingNegotiateClient {
    runtime: tokio::runtime::Runtime,
    client: NegotiateClient,
}

impl fmt::Debug for BlockingNegotiateClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingNegotiateClient")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl BlockingNegotiateClient {
    /// Wrap an existing Negotiate client.
    pub fn new(client: NegotiateClient) -> Result<Self, Error> {
        Ok(Self {
            runtime: blocking_runtime()?,
            client,
        })
    }

    /// Create a password-backed blocking Negotiate client.
    pub fn with_password(
        config: Config,
        client: Principal,
        password: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Self::new(NegotiateClient::with_password(config, client, password))
    }

    /// Create a keytab-backed blocking Negotiate client.
    pub fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Result<Self, Error> {
        Self::new(NegotiateClient::with_keytab(config, client, keytab))
    }

    /// Create a keytab-backed blocking Negotiate client by loading a file-backed keytab name.
    pub fn with_keytab_name(
        config: Config,
        client: Principal,
        keytab_name: impl AsRef<str>,
    ) -> Result<Self, Error> {
        Self::new(NegotiateClient::with_keytab_name(
            config,
            client,
            keytab_name,
        )?)
    }

    /// Create a cache-only blocking Negotiate client by loading a ccache name.
    pub fn from_ccache_name(config: Config, cache_name: impl AsRef<str>) -> Result<Self, Error> {
        Self::new(NegotiateClient::from_ccache_name(config, cache_name)?)
    }

    /// Create a cache-only blocking Negotiate client from the default credential cache.
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Self::new(NegotiateClient::from_default_ccache(config)?)
    }

    /// Create a cache-only blocking Negotiate client by loading the cache named by `KRB5CCNAME`.
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Self::new(NegotiateClient::from_ccache_env(config)?)
    }

    /// Borrow the wrapped async client.
    pub fn client(&self) -> &NegotiateClient {
        &self.client
    }

    /// Mutably borrow the wrapped async client.
    pub fn client_mut(&mut self) -> &mut NegotiateClient {
        &mut self.client
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    pub fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.authorization_context(service)?.header)
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    pub fn authorization_header_for_host(
        &mut self,
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<String, Error> {
        Ok(self.authorization_context_for_host(service, host)?.header)
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    pub fn authorization_context(
        &mut self,
        service: Principal,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.runtime
            .block_on(self.client.authorization_context(service))
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    pub fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: crate::spnego::InitiatorContextOptions,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.runtime.block_on(
            self.client
                .authorization_context_with_options(service, options),
        )
    }

    /// Build a SPNEGO initiator context for a host-based service.
    pub fn authorization_context_for_host(
        &mut self,
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.runtime
            .block_on(self.client.authorization_context_for_host(service, host))
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    pub fn change_password(
        &mut self,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.runtime
            .block_on(self.client.change_password(new_password, sender_address))
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    pub fn change_password_for(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.runtime.block_on(
            self.client
                .change_password_for(target, new_password, sender_address),
        )
    }

    /// Change this client's password using explicit kpasswd request metadata.
    pub fn change_password_with_options(
        &mut self,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.runtime.block_on(
            self.client
                .change_password_with_options(new_password, options),
        )
    }

    /// Change the given target principal's password using explicit kpasswd
    /// request metadata.
    pub fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: impl AsRef<[u8]>,
        options: KpasswdRequestOptions,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        self.runtime
            .block_on(
                self.client
                    .change_password_for_with_options(target, new_password, options),
            )
    }
}

fn blocking_runtime() -> Result<tokio::runtime::Runtime, Error> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}
