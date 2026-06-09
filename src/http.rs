//! HTTP and Tower adapters for SPNEGO Negotiate authentication.
//!
//! The plain HTTP helpers are available with the `http` feature. The Tower
//! middleware is available with the `tower` feature and validates service-side
//! `Authorization: Negotiate ...` headers before forwarding requests.

use crate::service::ServiceValidator;
use crate::spnego::{self, AcceptedContext};
use http_types::header::{AUTHORIZATION, HeaderValue, ToStrError, WWW_AUTHENTICATE};
use http_types::{Request, Response, StatusCode};

#[cfg(feature = "tokio")]
use crate::client::{Principal, TokioClient};
#[cfg(feature = "tower")]
use crate::config::Config;
#[cfg(feature = "tower")]
use crate::keytab::Keytab;
#[cfg(feature = "tower")]
use crate::service::{ApRepOptions, HostAddress};
#[cfg(feature = "tower")]
use std::borrow::Cow;
#[cfg(feature = "tower")]
use std::future::Future;
#[cfg(feature = "tower")]
use std::pin::Pin;
#[cfg(feature = "tower")]
use std::task::{Context, Poll};
#[cfg(feature = "tower")]
use std::time::{Duration, SystemTime};
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

/// HTTP Negotiate adapter result.
pub type Result<T> = std::result::Result<T, Error>;

/// HTTP Negotiate adapter error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request did not contain an Authorization header.
    #[error("missing HTTP Authorization header")]
    MissingAuthorization,

    /// The request or response header could not be represented as a string.
    #[error("invalid HTTP header value: {0}")]
    InvalidHeader(#[from] ToStrError),

    /// A response header value could not be constructed.
    #[error("invalid HTTP response header value: {0}")]
    InvalidHeaderValue(#[from] http_types::header::InvalidHeaderValue),

    /// SPNEGO/GSSAPI token processing failed.
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] crate::spnego::Error),

    /// Tokio client processing failed while building an HTTP request.
    #[cfg(feature = "tokio")]
    #[error("client error: {0}")]
    Client(#[from] crate::client::Error),

    /// Keytab loading failed while constructing HTTP middleware.
    #[cfg(feature = "tower")]
    #[error("keytab error: {0}")]
    Keytab(#[from] crate::keytab::Error),
}

/// Tower Negotiate middleware error.
#[cfg(feature = "tower")]
#[derive(Debug, thiserror::Error)]
pub enum TowerError<E> {
    /// HTTP Negotiate processing failed.
    #[error("{0}")]
    Http(#[from] Error),
    /// Wrapped Tower service failed.
    #[error("inner service error")]
    Inner(E),
}

/// Return the HTTP Authorization header as a string.
pub fn authorization_header<B>(request: &Request<B>) -> Result<&str> {
    request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Error::MissingAuthorization)?
        .to_str()
        .map_err(Error::InvalidHeader)
}

/// Set the HTTP Authorization header.
pub fn set_authorization_header<B>(request: &mut Request<B>, value: &str) -> Result<()> {
    request
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_str(value)?);
    Ok(())
}

/// Add a SPNEGO Authorization header to an HTTP request using a high-level client.
#[cfg(feature = "tokio")]
pub async fn authorize_request<B>(
    client: &mut TokioClient,
    request: &mut Request<B>,
    service: Principal,
) -> Result<()> {
    let header = client.spnego_header(service).await?;
    set_authorization_header(request, &header)
}

/// Validate the request's Negotiate header and attach the accepted context to extensions.
pub fn accept_request<B>(
    validator: &mut ServiceValidator<'_>,
    request: &mut Request<B>,
) -> Result<AcceptedContext> {
    let accepted = spnego::accept_sec_context_header(validator, authorization_header(request)?)?;
    request.extensions_mut().insert(accepted.clone());
    Ok(accepted)
}

/// Build a `401 Unauthorized` response that starts Negotiate authentication.
pub fn challenge_response<B: Default>() -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(spnego::HTTP_NEGOTIATE),
    );
    response
}

/// Build a `401 Unauthorized` response that carries a SPNEGO reject token.
pub fn reject_response<B: Default>() -> Result<Response<B>> {
    response_with_www_authenticate(StatusCode::UNAUTHORIZED, &spnego::reject_header()?)
}

fn response_with_www_authenticate<B: Default>(
    status: StatusCode,
    header: &str,
) -> Result<Response<B>> {
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_str(header)?);
    Ok(response)
}

/// Tower layer for service-side HTTP Negotiate validation.
#[cfg(feature = "tower")]
#[derive(Clone, Debug)]
pub struct NegotiateLayer<'a> {
    keytab: Cow<'a, Keytab>,
    validator: ValidatorOptions,
    response: NegotiateResponseOptions,
}

#[cfg(feature = "tower")]
impl<'a> NegotiateLayer<'a> {
    /// Create a Negotiate layer backed by a service keytab.
    pub fn new(keytab: &'a Keytab) -> Self {
        Self {
            keytab: Cow::Borrowed(keytab),
            validator: ValidatorOptions::default(),
            response: NegotiateResponseOptions::default(),
        }
    }

    /// Override the validation clock. Useful for deterministic tests.
    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.validator.now = Some(now);
        self
    }

    /// Override the maximum accepted clock skew.
    pub fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Self {
        self.validator.max_clock_skew = Some(max_clock_skew);
        self
    }

    /// Override the principal used for keytab lookup.
    pub fn with_keytab_principal<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.validator.keytab_principal = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Provide the client address observed by the service.
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.validator.client_address = Some(client_address);
        self
    }

    /// Require the ticket to contain client addresses.
    pub fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.validator.require_client_address = require_client_address;
        self
    }

    /// Control whether successful requests receive a `WWW-Authenticate` AP-REP token.
    pub fn with_ap_rep(mut self, emit_ap_rep: bool) -> Self {
        self.response.emit_ap_rep = emit_ap_rep;
        self
    }

    /// Override AP-REP response options.
    pub fn with_ap_rep_options(mut self, ap_rep_options: ApRepOptions) -> Self {
        self.response.ap_rep_options = ap_rep_options;
        self
    }

    /// Control whether invalid tokens receive a SPNEGO reject token.
    pub fn with_reject_invalid(mut self, reject_invalid: bool) -> Self {
        self.response.reject_invalid = reject_invalid;
        self
    }
}

#[cfg(feature = "tower")]
impl NegotiateLayer<'static> {
    /// Create a Negotiate layer from an owned service keytab.
    pub fn from_keytab(keytab: Keytab) -> Self {
        Self {
            keytab: Cow::Owned(keytab),
            validator: ValidatorOptions::default(),
            response: NegotiateResponseOptions::default(),
        }
    }

    /// Create a Negotiate layer by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    pub fn from_keytab_name(keytab_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self::from_keytab(Keytab::load_name(keytab_name)?))
    }

    /// Create a Negotiate layer from `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab_name(config: &Config) -> Result<Self> {
        Self::from_keytab_name(&config.libdefaults.default_keytab_name)
    }

    /// Create a Negotiate layer from the default keytab.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab(config: &Config) -> Result<Self> {
        Self::from_keytab_name(crate::keytab::default_keytab_name(
            &config.libdefaults.default_keytab_name,
        )?)
    }

    /// Create a Negotiate layer by loading the file keytab named by `KRB5_KTNAME`.
    pub fn from_keytab_env() -> Result<Self> {
        Ok(Self::from_keytab(Keytab::load_from_env()?))
    }
}

#[cfg(feature = "tower")]
impl<'layer, S> Layer<S> for NegotiateLayer<'layer> {
    type Service = NegotiateService<'layer, S>;

    fn layer(&self, inner: S) -> Self::Service {
        NegotiateService {
            inner,
            validator: self.validator.build(self.keytab.clone()),
            response: self.response.clone(),
        }
    }
}

/// Tower service for service-side HTTP Negotiate validation.
#[cfg(feature = "tower")]
#[derive(Debug)]
pub struct NegotiateService<'a, S> {
    inner: S,
    validator: ServiceValidator<'a>,
    response: NegotiateResponseOptions,
}

#[cfg(feature = "tower")]
impl<'a, S> NegotiateService<'a, S> {
    /// Wrap an inner service with default Negotiate validation.
    pub fn new(inner: S, keytab: &'a Keytab) -> Self {
        NegotiateLayer::new(keytab).layer(inner)
    }

    /// Return a shared reference to the wrapped service.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the wrapped service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

#[cfg(feature = "tower")]
impl<S> NegotiateService<'static, S> {
    /// Wrap an inner service with an owned keytab.
    pub fn from_keytab(inner: S, keytab: Keytab) -> Self {
        NegotiateLayer::from_keytab(keytab).layer(inner)
    }

    /// Wrap an inner service by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    pub fn from_keytab_name(inner: S, keytab_name: impl AsRef<str>) -> Result<Self> {
        Ok(NegotiateLayer::from_keytab_name(keytab_name)?.layer(inner))
    }

    /// Wrap an inner service by loading `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab_name(inner: S, config: &Config) -> Result<Self> {
        Ok(NegotiateLayer::from_default_keytab_name(config)?.layer(inner))
    }

    /// Wrap an inner service with the default keytab.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab(inner: S, config: &Config) -> Result<Self> {
        Ok(NegotiateLayer::from_default_keytab(config)?.layer(inner))
    }

    /// Wrap an inner service by loading the file keytab named by `KRB5_KTNAME`.
    pub fn from_keytab_env(inner: S) -> Result<Self> {
        Ok(NegotiateLayer::from_keytab_env()?.layer(inner))
    }
}

#[cfg(feature = "tower")]
impl<'a, S, ReqBody, ResBody> Service<Request<ReqBody>> for NegotiateService<'a, S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: 'static,
    S::Error: 'static,
    ResBody: Default + 'static,
{
    type Response = Response<ResBody>;
    type Error = TowerError<S::Error>;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(TowerError::Inner)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let accepted = match accept_request(&mut self.validator, &mut request) {
            Ok(accepted) => accepted,
            Err(Error::MissingAuthorization | Error::InvalidHeader(_)) => {
                return Box::pin(async { Ok(challenge_response()) });
            }
            Err(Error::Spnego(_)) => {
                let response = if self.response.reject_invalid {
                    reject_response().unwrap_or_else(|_| challenge_response())
                } else {
                    challenge_response()
                };
                return Box::pin(async move { Ok(response) });
            }
            Err(error) => {
                return Box::pin(async move { Err(TowerError::Http(error)) });
            }
        };

        let ap_rep_header = if self.response.emit_ap_rep {
            match accepted.ap_rep_response_header(self.response.ap_rep_options.clone()) {
                Ok(header) => Some(header),
                Err(error) => {
                    return Box::pin(async { Err(TowerError::Http(Error::Spnego(error))) });
                }
            }
        } else {
            None
        };

        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await.map_err(TowerError::Inner)?;
            if let Some(header) = ap_rep_header {
                let value = HeaderValue::from_str(&header)
                    .map_err(Error::InvalidHeaderValue)
                    .map_err(TowerError::Http)?;
                response.headers_mut().insert(WWW_AUTHENTICATE, value);
            }
            Ok(response)
        })
    }
}

#[cfg(feature = "tower")]
#[derive(Clone, Debug, Default)]
struct ValidatorOptions {
    max_clock_skew: Option<Duration>,
    now: Option<SystemTime>,
    keytab_principal: Option<Vec<String>>,
    client_address: Option<HostAddress>,
    require_client_address: bool,
}

#[cfg(feature = "tower")]
impl ValidatorOptions {
    fn build<'a>(&self, keytab: Cow<'a, Keytab>) -> ServiceValidator<'a> {
        let mut validator = ServiceValidator::from_keytab_cow(keytab);
        if let Some(now) = self.now {
            validator = validator.with_now(now);
        }
        if let Some(max_clock_skew) = self.max_clock_skew {
            validator = validator.with_max_clock_skew(max_clock_skew);
        }
        if let Some(keytab_principal) = &self.keytab_principal {
            validator = validator.with_keytab_principal(keytab_principal.clone());
        }
        if let Some(client_address) = &self.client_address {
            validator = validator.with_client_address(client_address.clone());
        }
        validator.require_client_address(self.require_client_address)
    }
}

#[cfg(feature = "tower")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NegotiateResponseOptions {
    emit_ap_rep: bool,
    ap_rep_options: ApRepOptions,
    reject_invalid: bool,
}

#[cfg(feature = "tower")]
impl Default for NegotiateResponseOptions {
    fn default() -> Self {
        Self {
            emit_ap_rep: true,
            ap_rep_options: ApRepOptions::default(),
            reject_invalid: true,
        }
    }
}
