//! Kerberos client-side exchange primitives.
//!
//! This module covers the first client slices needed for gokrb5-compatible
//! login flows: deterministic AS-REQ and TGS-REQ construction,
//! PA-ENC-TIMESTAMP and PA-TGS-REQ preauthentication, a KDC transport
//! boundary, encrypted-part validation, Tokio TCP/UDP transport, and
//! `krb5.conf`-driven KDC discovery.

#[cfg(feature = "tokio")]
use std::collections::BTreeMap;
#[cfg(feature = "tokio")]
use std::fmt;
#[cfg(feature = "tokio")]
use std::future::Future;
#[cfg(feature = "tokio")]
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ccache;
#[cfg(feature = "tokio")]
use crate::config::Config;
use crate::config::LibDefaults;
use crate::crypto::KerberosEtype;
use crate::keytab::{EncryptionKey, Keytab};
#[cfg(feature = "tokio")]
use hickory_resolver::{TokioResolver, proto::rr::RData};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(feature = "tokio")]
use zeroize::Zeroizing;

const KRB5_PVNO: i32 = 5;
const KRB_AS_REQ_MSG_TYPE: i32 = 10;
const KRB_AS_REP_MSG_TYPE: i32 = 11;
const KRB_TGS_REQ_MSG_TYPE: i32 = 12;
const KRB_TGS_REP_MSG_TYPE: i32 = 13;
const KRB_AP_REQ_MSG_TYPE: i32 = 14;
const KRB_ERROR_MSG_TYPE: i32 = 30;
const KRB_NT_PRINCIPAL: i32 = 1;
const KRB_NT_SRV_INST: i32 = 2;
const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_TKT_ENCTYPES: &[i32] = &[20, 19, 18, 17];
const DEFAULT_TGS_ENCTYPES: &[i32] = DEFAULT_TKT_ENCTYPES;
#[cfg(feature = "tokio")]
const DEFAULT_KDC_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "tokio")]
const DEFAULT_TCP_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
#[cfg(feature = "tokio")]
const MAX_UDP_DATAGRAM: usize = 65_507;
#[cfg(feature = "tokio")]
const DEFAULT_MAX_REFERRALS: usize = 5;

/// PA-ENC-TIMESTAMP preauthentication type.
pub const PA_ENC_TIMESTAMP: i32 = 2;

/// PA-TGS-REQ preauthentication type.
pub const PA_TGS_REQ: i32 = 1;

/// PA-ETYPE-INFO preauthentication hint type.
pub const PA_ETYPE_INFO: i32 = 11;

/// PA-ETYPE-INFO2 preauthentication hint type.
pub const PA_ETYPE_INFO2: i32 = 19;

/// PA-REQ-ENC-PA-REP marker used by modern gokrb5-compatible AS exchanges.
pub const PA_REQ_ENC_PA_REP: i32 = 149;

/// KDC error code for additional preauthentication required.
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;

/// Key usage for AS-REQ encrypted timestamp preauthentication.
pub const AS_REQ_PA_ENC_TIMESTAMP_USAGE: u32 = 1;

/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = 3;

/// Key usage for the TGS-REQ request-body checksum inside the authenticator.
pub const TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE: u32 = 6;

/// Key usage for the PA-TGS-REQ AP-REQ authenticator.
pub const TGS_REQ_AUTHENTICATOR_USAGE: u32 = 7;

/// Key usage for TGS-REP encrypted parts when encrypted with the TGT session key.
pub const TGS_REP_ENCPART_SESSION_KEY_USAGE: u32 = 8;

/// Raw KDC option mask for `renewable` in RFC 4120 bit-string order.
pub const KDC_OPTION_RENEWABLE: u32 = 0x0080_0000;

/// Raw KDC option mask for `renew` in RFC 4120 bit-string order.
pub const KDC_OPTION_RENEW: u32 = 0x0000_0002;

/// Kerberos principal identity used by client exchanges.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Create a principal.
    pub fn new<I, S>(realm: impl Into<String>, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            realm: realm.into(),
            name_type,
            components: components.into_iter().map(Into::into).collect(),
        }
    }

    /// Create a normal client principal.
    pub fn user(realm: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(realm, KRB_NT_PRINCIPAL, [name.into()])
    }

    /// Create the TGT service principal for a realm.
    pub fn tgt_service(realm: impl Into<String>) -> Self {
        let realm = realm.into();
        Self::new(realm.clone(), KRB_NT_SRV_INST, ["krbtgt".to_owned(), realm])
    }

    /// Principal components joined by `/`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Options for constructing an AS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsReqOptions {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
    /// Optional preauthentication data.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ using requested etype defaults.
    pub assume_preauthentication: bool,
}

impl AsReqOptions {
    /// Construct options with gokrb5-compatible AES defaults.
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TKT_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            assume_preauthentication: false,
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tkt_enctype_ids.is_empty() {
            DEFAULT_TKT_ENCTYPES.to_vec()
        } else {
            defaults.default_tkt_enctype_ids.clone()
        };
        options.kdc_option_bits = defaults.kdc_default_options;
        options
    }

    /// Override the requested ticket lifetime.
    pub fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    /// Override the renewable lifetime.
    pub fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    /// Override requested response encryption types.
    pub fn with_etypes(mut self, etypes: impl Into<Vec<i32>>) -> Self {
        self.etypes = etypes.into();
        self
    }

    /// Override KDC options using the raw krb5.conf bit representation.
    pub fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    /// Add preauthentication data.
    pub fn with_padata(mut self, padata: impl Into<Vec<rasn_kerberos::PaData>>) -> Self {
        self.padata = padata.into();
        self
    }

    /// Send PA-ENC-TIMESTAMP in the first AS-REQ.
    pub fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }
}

/// Options for constructing a TGS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TgsReqOptions {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested service-ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
}

impl TgsReqOptions {
    /// Construct options with gokrb5-compatible AES defaults.
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TGS_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tgs_enctype_ids.is_empty() {
            DEFAULT_TGS_ENCTYPES.to_vec()
        } else {
            defaults.default_tgs_enctype_ids.clone()
        };
        options.kdc_option_bits = defaults.kdc_default_options;
        options
    }

    /// Override the requested service-ticket lifetime.
    pub fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    /// Override the renewable lifetime.
    pub fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    /// Override requested response encryption types.
    pub fn with_etypes(mut self, etypes: impl Into<Vec<i32>>) -> Self {
        self.etypes = etypes.into();
        self
    }

    /// Override KDC options using the raw krb5.conf bit representation.
    pub fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    /// Add the TGS renewal flags used for renewing an existing ticket.
    pub fn with_renewal(mut self) -> Self {
        self.kdc_option_bits = renewal_kdc_option_bits(self.kdc_option_bits);
        self
    }
}

/// Encoded AS-REQ plus validation metadata needed when processing the AS-REP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltAsReq {
    /// ASN.1 AS-REQ message.
    pub message: rasn_kerberos::AsReq,
    /// DER-encoded AS-REQ bytes suitable for KDC transport.
    pub der: Vec<u8>,
    /// Request client principal.
    pub client: Principal,
    /// Request service principal.
    pub service: Principal,
    /// Request nonce.
    pub nonce: u32,
}

/// Encoded TGS-REQ plus validation metadata needed when processing the TGS-REP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltTgsReq {
    /// ASN.1 TGS-REQ message.
    pub message: rasn_kerberos::TgsReq,
    /// DER-encoded TGS-REQ bytes suitable for KDC transport.
    pub der: Vec<u8>,
    /// Request client principal.
    pub client: Principal,
    /// Requested service principal.
    pub service: Principal,
    /// Realm contacted for the TGS exchange.
    pub kdc_realm: String,
    /// Request nonce.
    pub nonce: u32,
}

/// Successful AS-REP processing result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsRepSession {
    /// Client identity returned by the KDC.
    pub client: Principal,
    /// Service identity returned by the KDC.
    pub service: Principal,
    /// Session key issued by the KDC.
    pub session_key: EncryptionKey,
    /// DER-encoded ticket from the AS-REP.
    pub ticket: Vec<u8>,
    /// Ticket flags as raw ccache bytes.
    pub ticket_flags: [u8; 4],
    /// Initial authentication time.
    pub auth_time: SystemTime,
    /// Ticket start time, or auth time when start time is absent.
    pub start_time: SystemTime,
    /// Ticket end time.
    pub end_time: SystemTime,
    /// Renewable-until time, when supplied.
    pub renew_till: Option<SystemTime>,
}

impl AsRepSession {
    /// Convert this AS-REP result into the existing MIT ccache credential shape.
    pub fn to_ccache_credential(&self) -> Result<ccache::Credential, Error> {
        Ok(ccache::Credential {
            client: ccache_principal(&self.client),
            server: ccache_principal(&self.service),
            key: ccache::EncryptionKey {
                etype: self.session_key.etype,
                value: self.session_key.value.clone(),
            },
            times: ccache::CredentialTimes {
                auth_time: system_time_to_u32_seconds(self.auth_time)?,
                start_time: system_time_to_u32_seconds(self.start_time)?,
                end_time: system_time_to_u32_seconds(self.end_time)?,
                renew_till: self
                    .renew_till
                    .map(system_time_to_u32_seconds)
                    .transpose()?
                    .unwrap_or_default(),
            },
            is_skey: false,
            ticket_flags: self.ticket_flags,
            addresses: Vec::new(),
            auth_data: Vec::new(),
            ticket: self.ticket.clone(),
            second_ticket: Vec::new(),
        })
    }
}

/// Successful TGS-REP processing result.
///
/// The ticket/session material is the same shape as an AS-REP result and can
/// be written to the existing ccache credential representation.
pub type TgsRepSession = AsRepSession;

/// Runtime-neutral boundary for KDC request/response transport.
pub trait KdcTransport {
    /// Send an encoded KDC request and return the encoded KDC response.
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Parsed KRB-ERROR returned by a KDC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdcError {
    /// Kerberos error code.
    pub error_code: i32,
    /// Optional human-readable error text.
    pub text: Option<String>,
    /// Client principal carried by the error, when present.
    pub client: Option<Principal>,
    /// Service principal that issued the error.
    pub service: Principal,
    /// Raw e-data bytes, when present.
    pub e_data: Option<Vec<u8>>,
    /// Parsed METHOD-DATA PA-DATA values for preauthentication errors.
    pub method_data: Vec<rasn_kerberos::PaData>,
    /// Parsed PA-ETYPE-INFO2/PA-ETYPE-INFO key derivation hints.
    pub preauth_key_info: Vec<PreauthKeyInfo>,
}

/// KDC hint for deriving or selecting a preauthentication key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreauthKeyInfo {
    /// Encryption type requested by the KDC.
    pub etype: i32,
    /// Optional password salt.
    pub salt: Option<String>,
    /// Optional string-to-key parameters as raw bytes.
    pub s2kparams: Option<Vec<u8>>,
}

/// KDC wire protocol for Tokio transport operations.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KdcProtocol {
    /// RFC 4120 UDP transport with raw DER request and response datagrams.
    Udp,
    /// RFC 4120 TCP transport with a four-byte big-endian length prefix.
    Tcp,
}

/// Source used to discover a KDC endpoint.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KdcEndpointSource {
    /// Endpoint came from a `[realms]` `kdc = ...` entry.
    Config,
    /// Endpoint came from `_kerberos._udp` or `_kerberos._tcp` DNS SRV lookup.
    DnsSrv,
}

/// One KDC endpoint discovered for a realm.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KdcEndpoint {
    /// Wire protocol to use for this endpoint.
    pub protocol: KdcProtocol,
    /// Host name or IP literal.
    pub host: String,
    /// KDC port.
    pub port: u16,
    /// How this endpoint was discovered.
    pub source: KdcEndpointSource,
}

/// Long-term credential source used by [`TokioClient`].
#[cfg(feature = "tokio")]
#[derive(Clone, Eq, PartialEq)]
pub enum TokioClientCredentials {
    /// Password credential for AS login.
    Password(Zeroizing<Vec<u8>>),
    /// Keytab credential for AS login.
    Keytab(Keytab),
}

#[cfg(feature = "tokio")]
impl fmt::Debug for TokioClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<redacted>)"),
            Self::Keytab(keytab) => f
                .debug_struct("Keytab")
                .field("entries", &keytab.entries().len())
                .finish(),
        }
    }
}

/// High-level Tokio Kerberos client with TGT and service-ticket caching.
#[cfg(feature = "tokio")]
#[derive(Clone, Eq, PartialEq)]
pub struct TokioClient {
    config: Config,
    protocol: KdcProtocol,
    transport: TokioKdcTransport,
    client: Principal,
    credentials: Option<TokioClientCredentials>,
    tgt: Option<AsRepSession>,
    service_tickets: BTreeMap<String, TgsRepSession>,
    assume_preauthentication: bool,
}

#[cfg(feature = "tokio")]
impl fmt::Debug for TokioClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioClient")
            .field("config", &self.config)
            .field("protocol", &self.protocol)
            .field("transport", &self.transport)
            .field("client", &self.client)
            .field("credentials", &self.credentials)
            .field("has_tgt", &self.tgt.is_some())
            .field("cached_service_tickets", &self.service_tickets.len())
            .field("assume_preauthentication", &self.assume_preauthentication)
            .finish()
    }
}

#[cfg(feature = "tokio")]
impl TokioClient {
    /// Create a password-backed client using KDCs discovered from config.
    pub fn with_password(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        password: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            config,
            protocol,
            client,
            Some(TokioClientCredentials::Password(Zeroizing::new(
                password.into(),
            ))),
        )
    }

    /// Create a keytab-backed client using KDCs discovered from config.
    pub fn with_keytab(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: Keytab,
    ) -> Self {
        Self::new(
            config,
            protocol,
            client,
            Some(TokioClientCredentials::Keytab(keytab)),
        )
    }

    /// Create a cache-only client from a ccache.
    ///
    /// Cached TGTs and service tickets are reused and renewed when possible.
    /// If no live password or keytab credential is configured, expired
    /// non-renewable entries cannot be re-acquired from the KDC.
    pub fn from_ccache(config: Config, protocol: KdcProtocol, cache: &ccache::CCache) -> Self {
        let client = client_principal_from_ccache(cache.default_principal());
        let mut kerberos = Self::new(config, protocol, client, None);
        let now = SystemTime::now();
        for credential in cache.entries() {
            if !same_ccache_client_identity(&credential.client, cache.default_principal()) {
                continue;
            }
            let session = ccache_credential_session(credential);
            if is_tgt_principal(&session.service) {
                kerberos.tgt = Some(preferred_session_at(kerberos.tgt.take(), session, now));
            } else {
                kerberos.cache_service_ticket(session);
            }
        }
        kerberos
    }

    /// Create a cache-only client from a known TGT session.
    pub fn from_tgt_session(config: Config, protocol: KdcProtocol, tgt: AsRepSession) -> Self {
        let mut kerberos = Self::new(config, protocol, tgt.client.clone(), None);
        kerberos.tgt = Some(tgt);
        kerberos
    }

    /// Export current TGT and service-ticket state to a fresh MIT ccache.
    pub fn to_ccache(&self) -> Result<ccache::CCache, Error> {
        let mut cache = ccache::CCache::new(ccache_principal(&self.client));
        for credential in self.ccache_credentials()? {
            cache.upsert_credential(credential);
        }
        Ok(cache)
    }

    /// Replace this client's non-configuration entries in an existing ccache.
    ///
    /// X-CACHECONF metadata and entries for other clients are preserved. The
    /// ccache default principal is set to this client's principal.
    pub fn update_ccache(&self, cache: &mut ccache::CCache) -> Result<(), Error> {
        let client = ccache_principal(&self.client);
        *cache.default_principal_mut() = client.clone();
        cache.remove_entries_for_client(&client);
        for credential in self.ccache_credentials()? {
            cache.upsert_credential(credential);
        }
        Ok(())
    }

    /// Save current TGT and service-ticket state to a fresh ccache file.
    pub fn save_ccache(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.to_ccache()?.save(path)?;
        Ok(())
    }

    /// Load an existing ccache when present, update this client's entries, and save it.
    ///
    /// Missing files are created. Existing X-CACHECONF metadata and entries for
    /// other clients are preserved.
    pub fn update_ccache_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let mut cache = match ccache::CCache::load(path) {
            Ok(cache) => cache,
            Err(ccache::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                ccache::CCache::new(ccache_principal(&self.client))
            }
            Err(error) => return Err(error.into()),
        };
        self.update_ccache(&mut cache)?;
        cache.save(path)?;
        Ok(())
    }

    fn new(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        credentials: Option<TokioClientCredentials>,
    ) -> Self {
        Self {
            config,
            protocol,
            transport: TokioKdcTransport::new(),
            client,
            credentials,
            tgt: None,
            service_tickets: BTreeMap::new(),
            assume_preauthentication: false,
        }
    }

    /// Override the transport used for KDC exchanges.
    pub fn with_transport(mut self, transport: TokioKdcTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Configure whether AS login sends PA-ENC-TIMESTAMP in the first AS-REQ.
    pub fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }

    /// Parsed Kerberos configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Selected KDC wire protocol.
    pub fn protocol(&self) -> KdcProtocol {
        self.protocol
    }

    /// Client principal.
    pub fn client_principal(&self) -> &Principal {
        &self.client
    }

    /// Whether AS login sends PA-ENC-TIMESTAMP in the first AS-REQ.
    pub fn assume_preauthentication(&self) -> bool {
        self.assume_preauthentication
    }

    /// Current TGT session, when logged in or loaded from cache.
    pub fn tgt_session(&self) -> Option<&AsRepSession> {
        self.tgt.as_ref()
    }

    /// Number of cached service tickets.
    pub fn cached_service_ticket_count(&self) -> usize {
        self.service_tickets.len()
    }

    /// Clear cached service tickets without dropping the TGT.
    pub fn clear_service_ticket_cache(&mut self) {
        self.service_tickets.clear();
    }

    /// Insert or replace a service ticket in the cache.
    pub fn cache_service_ticket(&mut self, ticket: TgsRepSession) {
        let key = service_cache_key(&ticket.service);
        let ticket =
            preferred_session_at(self.service_tickets.remove(&key), ticket, SystemTime::now());
        self.service_tickets.insert(key, ticket);
    }

    /// Perform AS login with the configured long-term credential.
    pub async fn login(&mut self) -> Result<&AsRepSession, Error> {
        let Some(credentials) = self.credentials.clone() else {
            let Some(tgt) = self.tgt.clone() else {
                return Err(Error::NoClientCredentials);
            };
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) {
                return Ok(self.tgt.as_ref().expect("TGT was just checked"));
            }
            if session_renewable_at(&tgt, now) {
                return self.renew_tgt().await;
            }
            return Err(Error::NoClientCredentials);
        };
        let options = self.as_req_options()?;
        let session = match credentials {
            TokioClientCredentials::Password(password) => {
                self.transport
                    .login_tgt_with_password_config(
                        &self.config,
                        self.protocol,
                        self.client.clone(),
                        &password,
                        options,
                    )
                    .await?
            }
            TokioClientCredentials::Keytab(keytab) => {
                self.transport
                    .login_tgt_with_keytab_config(
                        &self.config,
                        self.protocol,
                        self.client.clone(),
                        &keytab,
                        options,
                    )
                    .await?
            }
        };

        self.tgt = Some(session);
        self.service_tickets.clear();
        Ok(self.tgt.as_ref().expect("TGT was just inserted"))
    }

    /// Renew the current TGT explicitly.
    pub async fn renew_tgt(&mut self) -> Result<&AsRepSession, Error> {
        let tgt = self.tgt.clone().ok_or(Error::NoTgtSession)?;
        let renewed = self
            .transport
            .renew_tgt_with_config(&self.config, self.protocol, &tgt, self.tgs_req_options()?)
            .await?;
        self.tgt = Some(renewed);
        self.service_tickets.clear();
        Ok(self.tgt.as_ref().expect("TGT was just inserted"))
    }

    /// Return a service ticket from cache or acquire one from a KDC.
    pub async fn get_service_ticket(&mut self, service: Principal) -> Result<TgsRepSession, Error> {
        let service = self.resolve_service_principal(service);
        let key = service_cache_key(&service);
        if let Some(ticket) = self.service_tickets.get(&key).cloned() {
            let now = SystemTime::now();
            if session_valid_at(&ticket, now) {
                return Ok(ticket);
            }
            if session_renewable_at(&ticket, now)
                && let Ok(renewed) = self
                    .transport
                    .renew_ticket_with_config(
                        &self.config,
                        self.protocol,
                        &ticket,
                        self.tgs_req_options()?,
                    )
                    .await
            {
                self.cache_service_ticket(renewed.clone());
                return Ok(renewed);
            }
        }

        let tgt = self.ensure_tgt().await?;
        let ticket = self
            .transport
            .get_service_ticket_with_referrals(
                &self.config,
                self.protocol,
                &tgt,
                service,
                self.tgs_req_options()?,
            )
            .await?;
        self.cache_service_ticket(ticket.clone());
        Ok(ticket)
    }

    /// Build a SPNEGO HTTP `Authorization` header for a service.
    #[cfg(feature = "spnego")]
    pub async fn spnego_header(&mut self, service: Principal) -> Result<String, Error> {
        self.spnego_header_with_options(service, crate::spnego::InitiatorContextOptions::new())
            .await
    }

    /// Build a SPNEGO HTTP `Authorization` header with explicit initiator options.
    #[cfg(feature = "spnego")]
    pub async fn spnego_header_with_options(
        &mut self,
        service: Principal,
        options: crate::spnego::InitiatorContextOptions,
    ) -> Result<String, Error> {
        let ticket = self.get_service_ticket(service).await?;
        Ok(crate::spnego::authorization_header(&ticket, options)?)
    }

    async fn ensure_tgt(&mut self) -> Result<AsRepSession, Error> {
        if let Some(tgt) = self.tgt.clone() {
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) {
                return Ok(tgt);
            }
            if session_renewable_at(&tgt, now) {
                return Ok(self.renew_tgt().await?.clone());
            }
        }

        if self.credentials.is_none() {
            return Err(Error::NoClientCredentials);
        }
        Ok(self.login().await?.clone())
    }

    fn as_req_options(&self) -> Result<AsReqOptions, Error> {
        Ok(AsReqOptions::from_libdefaults(
            SystemTime::now(),
            random_nonce()?,
            &self.config.libdefaults,
        )
        .with_assume_preauthentication(self.assume_preauthentication))
    }

    fn tgs_req_options(&self) -> Result<TgsReqOptions, Error> {
        Ok(TgsReqOptions::from_libdefaults(
            SystemTime::now(),
            random_nonce()?,
            &self.config.libdefaults,
        ))
    }

    fn resolve_service_principal(&self, mut service: Principal) -> Principal {
        if service.realm.is_empty() {
            service.realm =
                service_realm(&self.config, &service).unwrap_or_else(|| self.client.realm.clone());
        }
        service
    }

    fn ccache_credentials(&self) -> Result<Vec<ccache::Credential>, Error> {
        let mut credentials =
            Vec::with_capacity(usize::from(self.tgt.is_some()) + self.service_tickets.len());
        if let Some(tgt) = &self.tgt {
            credentials.push(tgt.to_ccache_credential()?);
        }
        for ticket in self.service_tickets.values() {
            credentials.push(ticket.to_ccache_credential()?);
        }
        Ok(credentials)
    }
}

#[cfg(feature = "tokio")]
impl KdcEndpoint {
    /// Create a configured endpoint from a `host[:port]` value.
    pub fn configured(protocol: KdcProtocol, value: &str) -> Result<Self, Error> {
        let (host, port) = parse_kdc_endpoint(value, 88)?;
        Ok(Self {
            protocol,
            host,
            port,
            source: KdcEndpointSource::Config,
        })
    }

    /// Return a display-friendly `host:port` authority.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Tokio-backed KDC transport for explicit TCP or UDP exchanges.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokioKdcTransport {
    timeout: Duration,
    udp_response_limit: usize,
    tcp_response_limit: usize,
}

#[cfg(feature = "tokio")]
impl Default for TokioKdcTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
impl TokioKdcTransport {
    /// Create a transport with conservative gokrb5-compatible defaults.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_KDC_TIMEOUT,
            udp_response_limit: MAX_UDP_DATAGRAM + 1,
            tcp_response_limit: DEFAULT_TCP_RESPONSE_LIMIT,
        }
    }

    /// Override the timeout applied to each KDC exchange.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the UDP receive buffer size.
    pub fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self {
        self.udp_response_limit = udp_response_limit;
        self
    }

    /// Override the maximum accepted TCP response body size.
    pub fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self {
        self.tcp_response_limit = tcp_response_limit;
        self
    }

    /// Send an encoded KDC request over UDP.
    pub async fn send_udp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        if request.len() > MAX_UDP_DATAGRAM {
            return Err(Error::UdpRequestTooLarge {
                actual: request.len(),
                limit: MAX_UDP_DATAGRAM,
            });
        }

        self.with_transport_timeout(async {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(addr).await?;
            socket.send(request).await?;

            let mut response = vec![0; self.udp_response_limit];
            let len = socket.recv(&mut response).await?;
            response.truncate(len);
            Ok(response)
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over RFC 4120 TCP framing.
    pub async fn send_tcp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        let request_len = request
            .len()
            .try_into()
            .map_err(|_| Error::TcpRequestTooLarge {
                actual: request.len(),
            })?;

        self.with_transport_timeout(async {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&u32::to_be_bytes(request_len)).await?;
            stream.write_all(request).await?;

            let mut header = [0; 4];
            stream.read_exact(&mut header).await?;
            let response_len = u32::from_be_bytes(header);
            let response_len_usize = response_len as usize;
            if response_len_usize > self.tcp_response_limit {
                return Err(Error::TcpResponseTooLarge {
                    actual: response_len,
                    limit: self.tcp_response_limit,
                });
            }

            let mut response = vec![0; response_len_usize];
            stream.read_exact(&mut response).await?;
            Ok(response)
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over the selected protocol.
    pub async fn send<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        match protocol {
            KdcProtocol::Udp => self.send_udp(addr, request).await,
            KdcProtocol::Tcp => self.send_tcp(addr, request).await,
        }
    }

    /// Discover KDC endpoints for a realm using `krb5.conf` semantics.
    ///
    /// Configured `[realms]` KDCs are preferred. DNS SRV lookup is attempted
    /// only when no KDCs are configured and `dns_lookup_kdc = true`.
    pub async fn discover_kdcs(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        if let Some(realm_entry) = config.realm(realm)
            && !realm_entry.kdc.is_empty()
        {
            return realm_entry
                .kdc
                .iter()
                .map(|value| KdcEndpoint::configured(protocol, value))
                .collect();
        }

        if config.libdefaults.dns_lookup_kdc {
            return self.discover_kdcs_with_dns(realm, protocol).await;
        }

        if config.realm(realm).is_some() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Err(crate::config::Error::NoRealm(realm.to_owned()).into())
        }
    }

    /// Send an encoded request to the first reachable KDC discovered from config.
    pub async fn send_to_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send an AS-REQ through Tokio transport and process the returned AS-REP.
    pub async fn exchange_as_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send an AS-REQ through a config-discovered KDC and process the AS-REP.
    pub async fn exchange_as_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send a TGS-REQ through Tokio transport and process the returned TGS-REP.
    pub async fn exchange_tgs_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Send a TGS-REQ through a config-discovered KDC and process the TGS-REP.
    pub async fn exchange_tgs_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
            .await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Renew an existing TGT through an explicit KDC endpoint.
    pub async fn renew_tgt<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        tgt: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs,
    {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing TGT through a config-discovered KDC.
    pub async fn renew_tgt_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing service ticket through an explicit KDC endpoint.
    pub async fn renew_ticket<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        ticket: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs,
    {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &ticket.session_key)
            .await
    }

    /// Renew an existing service ticket through a config-discovered KDC.
    pub async fn renew_ticket_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        ticket: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &ticket.session_key)
            .await
    }

    /// Acquire a service ticket, following cross-realm TGS referrals.
    ///
    /// The supplied `tgt` is used as the starting TGT. If the service belongs
    /// to a different realm, this first obtains referral TGTs until it can ask
    /// the target realm for the final service ticket.
    pub async fn get_service_ticket_with_referrals(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        self.get_service_ticket_with_referrals_limit(
            config,
            protocol,
            tgt,
            service,
            options,
            DEFAULT_MAX_REFERRALS,
        )
        .await
    }

    /// Acquire a service ticket with an explicit referral limit.
    pub async fn get_service_ticket_with_referrals_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        mut service: Principal,
        options: TgsReqOptions,
        max_referrals: usize,
    ) -> Result<TgsRepSession, Error> {
        let mut current_tgt = tgt.clone();
        let mut current_realm =
            tgt_realm(&current_tgt).ok_or_else(|| Error::InvalidReferralTicket {
                service: current_tgt.service.name(),
            })?;
        if service.realm.is_empty() {
            service.realm =
                service_realm(config, &service).unwrap_or_else(|| current_realm.clone());
        }
        let target_realm = service.realm.clone();

        for referrals in 0..=max_referrals {
            let requested_service = if current_realm == target_realm {
                service.clone()
            } else {
                Principal::new(
                    current_realm.clone(),
                    KRB_NT_SRV_INST,
                    ["krbtgt".to_owned(), target_realm.clone()],
                )
            };
            let request = build_tgs_req_for_realm(
                &current_tgt,
                current_realm.clone(),
                requested_service,
                options.clone(),
            )?;
            let response = self
                .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
                .await?;
            let ticket =
                process_tgs_rep_with_referral(&request, &response, &current_tgt.session_key)?;

            if principal_matches(&ticket.service, &service) {
                return Ok(ticket);
            }

            let referred_realm =
                tgt_realm(&ticket).ok_or_else(|| Error::ServicePrincipalMismatch {
                    expected: service.name(),
                    actual: ticket.service.name(),
                })?;
            if referred_realm == current_realm {
                return Err(Error::InvalidReferralTicket {
                    service: ticket.service.name(),
                });
            }

            current_realm = referred_realm;
            current_tgt = ticket;

            if referrals == max_referrals {
                return Err(Error::MaxReferralDepth { max: max_referrals });
            }
        }

        Err(Error::MaxReferralDepth { max: max_referrals })
    }

    /// Perform a TGT AS login using password credentials and KDC preauth hints.
    pub async fn login_tgt_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request = password_initial_as_req(client.clone(), password, options.clone())?;
        let initial_response = self
            .send(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, password, options, &initial_response)?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a password TGT AS login using KDCs discovered from `krb5.conf`.
    pub async fn login_tgt_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let initial_request = password_initial_as_req(client.clone(), password, options.clone())?;
        let initial_response = self
            .send_to_realm(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, password, options, &initial_response)?;
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a TGT AS login using keytab credentials and KDC preauth hints.
    pub async fn login_tgt_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request = keytab_initial_as_req(client.clone(), keytab, options.clone())?;
        let initial_response = self
            .send(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, keytab, options, &initial_response)?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a keytab TGT AS login using KDCs discovered from `krb5.conf`.
    pub async fn login_tgt_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let initial_request = keytab_initial_as_req(client.clone(), keytab, options.clone())?;
        let initial_response = self
            .send_to_realm(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, keytab, options, &initial_response)?;
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(&request, &response, &reply_key)
    }

    async fn discover_kdcs_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let service = match protocol {
            KdcProtocol::Udp => "_kerberos._udp",
            KdcProtocol::Tcp => "_kerberos._tcp",
        };
        let query = format!("{service}.{realm}.");
        let resolver = TokioResolver::builder_tokio()
            .map_err(|source| Error::DnsResolverConfig(source.to_string()))?
            .build()
            .map_err(|source| Error::DnsResolverConfig(source.to_string()))?;
        let lookup = resolver
            .srv_lookup(query.as_str())
            .await
            .map_err(|source| Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol,
                message: source.to_string(),
            })?;

        let mut records = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(srv) => Some(srv),
                _ => None,
            })
            .map(|srv| {
                (
                    srv.priority,
                    srv.weight,
                    srv.target.to_utf8().trim_end_matches('.').to_owned(),
                    srv.port,
                )
            })
            .filter(|(_, _, target, _)| !target.is_empty() && target != ".")
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
        });

        let endpoints = records
            .into_iter()
            .map(|(_, _, host, port)| KdcEndpoint {
                protocol,
                host,
                port,
                source: KdcEndpointSource::DnsSrv,
            })
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Ok(endpoints)
        }
    }

    async fn send_to_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if endpoints.is_empty() {
            return Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            });
        }

        let mut failures = Vec::new();
        for endpoint in endpoints {
            match self
                .send(
                    endpoint.protocol,
                    (endpoint.host.as_str(), endpoint.port),
                    request,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => failures.push(format!("{}: {error}", endpoint.authority())),
            }
        }

        Err(Error::KdcEndpointFailures {
            realm: realm.to_owned(),
            protocol,
            failures,
        })
    }

    async fn with_transport_timeout<F, T>(&self, operation: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        tokio::time::timeout(self.timeout, operation)
            .await
            .map_err(|_| Error::TransportTimeout(self.timeout))?
    }
}

/// Build a TGT AS-REQ for the supplied client principal.
pub fn build_tgt_as_req(client: Principal, options: AsReqOptions) -> Result<BuiltAsReq, Error> {
    let service = Principal::tgt_service(client.realm.clone());
    build_as_req(client, service, options)
}

/// Build an AS-REQ for an explicit service principal.
pub fn build_as_req(
    client: Principal,
    service: Principal,
    options: AsReqOptions,
) -> Result<BuiltAsReq, Error> {
    if options.etypes.is_empty() {
        return Err(Error::EmptyEtypes);
    }

    let till = options
        .now
        .checked_add(options.ticket_lifetime)
        .ok_or(Error::TimeOverflow)?;
    let renew_till = options
        .renew_lifetime
        .map(|duration| options.now.checked_add(duration).ok_or(Error::TimeOverflow))
        .transpose()?;
    let padata = (!options.padata.is_empty()).then_some(options.padata);
    let kdc_option_bits = request_kdc_option_bits(options.kdc_option_bits, options.renew_lifetime);
    let message = rasn_kerberos::AsReq(rasn_kerberos::KdcReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AS_REQ_MSG_TYPE),
        padata,
        req_body: rasn_kerberos::KdcReqBody {
            kdc_options: kdc_options_from_bits(kdc_option_bits),
            cname: Some(principal_to_rasn(&client)?),
            realm: kerberos_string(&client.realm)?,
            sname: Some(principal_to_rasn(&service)?),
            from: None,
            till: kerberos_time_from_system_time(till)?,
            rtime: renew_till.map(kerberos_time_from_system_time).transpose()?,
            nonce: options.nonce,
            etype: options.etypes,
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    let der = encode("AS-REQ", &message)?;

    Ok(BuiltAsReq {
        message,
        der,
        client,
        service,
        nonce: options.nonce,
    })
}

/// Build encrypted timestamp preauthentication data with an explicit confounder.
pub fn pa_enc_timestamp_with_confounder(
    key: &EncryptionKey,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
    kvno: Option<u32>,
) -> Result<rasn_kerberos::PaData, Error> {
    let enc_ts = rasn_kerberos::PaEncTsEnc {
        patimestamp: kerberos_time_from_system_time(timestamp)?,
        pausec: Some(rasn::types::Integer::from(cusec)),
    };
    let plaintext = encode("PA-ENC-TS-ENC", &enc_ts)?;
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        AS_REQ_PA_ENC_TIMESTAMP_USAGE,
        confounder,
    )?;
    let encrypted = rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    };
    Ok(rasn_kerberos::PaData {
        r#type: PA_ENC_TIMESTAMP,
        value: encode("PA-ENC-TIMESTAMP", &encrypted)?.into(),
    })
}

/// Build encrypted timestamp preauthentication data with random confounder bytes.
pub fn pa_enc_timestamp(
    key: &EncryptionKey,
    timestamp: SystemTime,
    cusec: u32,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::PaData, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    pa_enc_timestamp_with_confounder(key, timestamp, cusec, &confounder, kvno)
}

/// Build a TGT AS-REQ with PA-ENC-TIMESTAMP preauthentication.
pub fn build_preauthenticated_tgt_as_req(
    client: Principal,
    mut options: AsReqOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<BuiltAsReq, Error> {
    let (timestamp, cusec) = current_preauth_time()?;
    options
        .padata
        .retain(|padata| padata.r#type != PA_ENC_TIMESTAMP);
    options
        .padata
        .push(pa_enc_timestamp(key, timestamp, cusec, kvno)?);
    build_tgt_as_req(client, options)
}

/// Build a TGS-REQ for a service ticket using the supplied TGT session.
pub fn build_tgs_req(
    tgt: &AsRepSession,
    service: Principal,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm(tgt, service.realm.clone(), service, options)
}

/// Build a TGS-REQ for a service ticket while contacting an explicit KDC realm.
pub fn build_tgs_req_for_realm(
    tgt: &AsRepSession,
    kdc_realm: impl Into<String>,
    service: Principal,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_tgs_req_for_realm_with_confounder(
        tgt,
        kdc_realm,
        service,
        options,
        timestamp,
        cusec,
        &confounder,
    )
}

/// Build a TGS-REQ with an explicit authenticator timestamp and confounder.
pub fn build_tgs_req_with_confounder(
    tgt: &AsRepSession,
    service: Principal,
    options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm_with_confounder(
        tgt,
        service.realm.clone(),
        service,
        options,
        timestamp,
        cusec,
        confounder,
    )
}

/// Build a TGS-REQ for an explicit KDC realm, timestamp, and confounder.
pub fn build_tgs_req_for_realm_with_confounder(
    tgt: &AsRepSession,
    kdc_realm: impl Into<String>,
    service: Principal,
    options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    if options.etypes.is_empty() {
        return Err(Error::EmptyEtypes);
    }

    let kdc_realm = kdc_realm.into();
    let ticket = decode::<rasn_kerberos::Ticket>("Ticket", &tgt.ticket)?;
    let till = options
        .now
        .checked_add(options.ticket_lifetime)
        .ok_or(Error::TimeOverflow)?;
    let renew_till = options
        .renew_lifetime
        .map(|duration| options.now.checked_add(duration).ok_or(Error::TimeOverflow))
        .transpose()?;
    let cname = principal_to_rasn(&tgt.client)?;
    let kdc_option_bits = request_kdc_option_bits(options.kdc_option_bits, options.renew_lifetime);
    let req_body = rasn_kerberos::KdcReqBody {
        kdc_options: kdc_options_from_bits(kdc_option_bits),
        cname: Some(cname.clone()),
        realm: kerberos_string(&kdc_realm)?,
        sname: Some(principal_to_rasn(&service)?),
        from: None,
        till: kerberos_time_from_system_time(till)?,
        rtime: renew_till.map(kerberos_time_from_system_time).transpose()?,
        nonce: options.nonce,
        etype: options.etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let req_body_der = encode("TGS-REQ-BODY", &req_body)?;
    let etype = KerberosEtype::from_etype_id(tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(tgt.session_key.etype))?;
    let checksum = etype.checksum(
        &tgt.session_key.value,
        &req_body_der,
        TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
    )?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: rasn::types::Integer::from(KRB5_PVNO),
        crealm: ticket.realm.clone(),
        cname,
        cksum: Some(rasn_kerberos::Checksum {
            r#type: etype.checksum_type_id(),
            checksum: checksum.into(),
        }),
        cusec: rasn::types::Integer::from(cusec),
        ctime: kerberos_time_from_system_time(timestamp)?,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let authenticator_der = encode("Authenticator", &authenticator)?;
    let cipher = etype.encrypt_message_with_confounder(
        &tgt.session_key.value,
        &authenticator_der,
        TGS_REQ_AUTHENTICATOR_USAGE,
        confounder,
    )?;
    let authenticator_kvno = ticket.enc_part.kvno;
    let ap_req = rasn_kerberos::ApReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AP_REQ_MSG_TYPE),
        ap_options: rasn_kerberos::ApOptions(zero_kerberos_flags()),
        ticket,
        authenticator: rasn_kerberos::EncryptedData {
            etype: tgt.session_key.etype,
            kvno: authenticator_kvno,
            cipher: cipher.into(),
        },
    };
    let padata = rasn_kerberos::PaData {
        r#type: PA_TGS_REQ,
        value: encode("PA-TGS-REQ AP-REQ", &ap_req)?.into(),
    };
    let message = rasn_kerberos::TgsReq(rasn_kerberos::KdcReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_TGS_REQ_MSG_TYPE),
        padata: Some(vec![padata]),
        req_body,
    });
    let der = encode("TGS-REQ", &message)?;

    Ok(BuiltTgsReq {
        message,
        der,
        client: tgt.client.clone(),
        kdc_realm,
        service,
        nonce: options.nonce,
    })
}

/// Build a TGS-REQ that renews an existing TGT session.
pub fn build_tgt_renewal_req(
    tgt: &AsRepSession,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    let realm = tgt_realm(tgt).ok_or_else(|| Error::InvalidTgtSession {
        service: tgt.service.name(),
    })?;
    build_tgs_req_for_realm(
        tgt,
        realm.clone(),
        Principal::tgt_service(realm),
        options.with_renewal(),
    )
}

/// Build a deterministic TGT renewal request with an explicit authenticator timestamp and confounder.
pub fn build_tgt_renewal_req_with_confounder(
    tgt: &AsRepSession,
    options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    let realm = tgt_realm(tgt).ok_or_else(|| Error::InvalidTgtSession {
        service: tgt.service.name(),
    })?;
    build_tgs_req_for_realm_with_confounder(
        tgt,
        realm.clone(),
        Principal::tgt_service(realm),
        options.with_renewal(),
        timestamp,
        cusec,
        confounder,
    )
}

/// Build a TGS-REQ that renews an existing service ticket.
pub fn build_ticket_renewal_req(
    ticket: &AsRepSession,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm(
        ticket,
        ticket.service.realm.clone(),
        ticket.service.clone(),
        options.with_renewal(),
    )
}

/// Build a deterministic service-ticket renewal request with an explicit authenticator timestamp and confounder.
pub fn build_ticket_renewal_req_with_confounder(
    ticket: &AsRepSession,
    options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm_with_confounder(
        ticket,
        ticket.service.realm.clone(),
        ticket.service.clone(),
        options.with_renewal(),
        timestamp,
        cusec,
        confounder,
    )
}

/// Send an AS-REQ through a transport and process the returned AS-REP.
pub fn exchange_as_req<T>(
    transport: &mut T,
    request: &BuiltAsReq,
    reply_key: &EncryptionKey,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(request, &response, reply_key)
}

/// Send a TGS-REQ through a transport and process the returned TGS-REP.
pub fn exchange_tgs_req<T>(
    transport: &mut T,
    request: &BuiltTgsReq,
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let response = transport.send(&request.kdc_realm, &request.der)?;
    process_tgs_rep(request, &response, tgs_session_key)
}

/// Renew an existing TGT through a runtime-neutral transport.
pub fn renew_tgt<T>(
    transport: &mut T,
    tgt: &AsRepSession,
    options: TgsReqOptions,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_tgt_renewal_req(tgt, options)?;
    exchange_tgs_req(transport, &request, &tgt.session_key)
}

/// Renew an existing service ticket through a runtime-neutral transport.
pub fn renew_ticket<T>(
    transport: &mut T,
    ticket: &AsRepSession,
    options: TgsReqOptions,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_ticket_renewal_req(ticket, options)?;
    exchange_tgs_req(transport, &request, &ticket.session_key)
}

/// Perform a TGT AS login using password credentials and KDC preauth hints.
pub fn login_tgt_with_password<T>(
    transport: &mut T,
    client: Principal,
    password: &[u8],
    options: AsReqOptions,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request = password_initial_as_req(client.clone(), password, options.clone())?;
    let initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
    {
        return Ok(session);
    }
    let (request, reply_key) =
        password_preauth_request(client, password, options, &initial_response)?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(&request, &response, &reply_key)
}

/// Perform a TGT AS login using keytab credentials and KDC preauth hints.
pub fn login_tgt_with_keytab<T>(
    transport: &mut T,
    client: Principal,
    keytab: &Keytab,
    options: AsReqOptions,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request = keytab_initial_as_req(client.clone(), keytab, options.clone())?;
    let initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
    {
        return Ok(session);
    }
    let (request, reply_key) = keytab_preauth_request(client, keytab, options, &initial_response)?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(&request, &response, &reply_key)
}

/// Decrypt and validate an AS-REP against the original AS-REQ.
pub fn process_as_rep(
    request: &BuiltAsReq,
    bytes: &[u8],
    reply_key: &EncryptionKey,
) -> Result<AsRepSession, Error> {
    let as_rep = decode::<rasn_kerberos::AsRep>("AS-REP", bytes)?;
    let kdc_rep = &as_rep.0;
    validate_integer("pvno", &kdc_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_rep.msg_type, KRB_AS_REP_MSG_TYPE)?;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::ClientPrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    if reply_key.etype != kdc_rep.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: reply_key.etype,
            encrypted_data_etype: kdc_rep.enc_part.etype,
        });
    }

    let plaintext = decrypt_encrypted_data(
        kdc_rep.enc_part.etype,
        &reply_key.value,
        kdc_rep.enc_part.cipher.as_ref(),
        AS_REP_ENCPART_USAGE,
    )?;
    let enc_part = decode_as_rep_enc_part(&plaintext)?;

    if enc_part.nonce != request.nonce {
        return Err(Error::NonceMismatch {
            expected: request.nonce,
            actual: enc_part.nonce,
        });
    }

    let enc_part_service = principal_from_parts(&enc_part.srealm, &enc_part.sname)?;
    if !principal_matches(&enc_part_service, &request.service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: request.service.name(),
            actual: enc_part_service.name(),
        });
    }

    let ticket_service = principal_from_parts(&kdc_rep.ticket.realm, &kdc_rep.ticket.sname)?;
    if !principal_matches(&ticket_service, &enc_part_service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: enc_part_service.name(),
            actual: ticket_service.name(),
        });
    }

    let ticket = encode("Ticket", &kdc_rep.ticket)?;
    Ok(AsRepSession {
        client,
        service: enc_part_service,
        session_key: encryption_key_from_rasn(&enc_part.key),
        ticket,
        ticket_flags: ticket_flags_to_bytes(&enc_part.flags),
        auth_time: system_time_from_kerberos_time(&enc_part.auth_time)?,
        start_time: system_time_from_kerberos_time(
            enc_part.start_time.as_ref().unwrap_or(&enc_part.auth_time),
        )?,
        end_time: system_time_from_kerberos_time(&enc_part.end_time)?,
        renew_till: enc_part
            .renew_till
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

/// Decrypt and validate a TGS-REP against the original TGS-REQ.
pub fn process_tgs_rep(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error> {
    process_tgs_rep_inner(request, bytes, tgs_session_key, false)
}

/// Decrypt and validate a TGS-REP, permitting intermediate referral TGTs.
pub fn process_tgs_rep_with_referral(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error> {
    process_tgs_rep_inner(request, bytes, tgs_session_key, true)
}

fn process_tgs_rep_inner(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
    allow_referral: bool,
) -> Result<TgsRepSession, Error> {
    let tgs_rep = decode::<rasn_kerberos::TgsRep>("TGS-REP", bytes)?;
    let kdc_rep = &tgs_rep.0;
    validate_integer("pvno", &kdc_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_rep.msg_type, KRB_TGS_REP_MSG_TYPE)?;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::ClientPrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    if tgs_session_key.etype != kdc_rep.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: tgs_session_key.etype,
            encrypted_data_etype: kdc_rep.enc_part.etype,
        });
    }

    let plaintext = decrypt_encrypted_data(
        kdc_rep.enc_part.etype,
        &tgs_session_key.value,
        kdc_rep.enc_part.cipher.as_ref(),
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
    )?;
    let enc_part = decode_tgs_rep_enc_part(&plaintext)?;

    if enc_part.nonce != request.nonce {
        return Err(Error::NonceMismatch {
            expected: request.nonce,
            actual: enc_part.nonce,
        });
    }

    let enc_part_service = principal_from_parts(&enc_part.srealm, &enc_part.sname)?;
    let referral = allow_referral
        && is_tgt_principal(&enc_part_service)
        && !principal_matches(&enc_part_service, &request.service);
    if !principal_matches(&enc_part_service, &request.service) && !referral {
        return Err(Error::ServicePrincipalMismatch {
            expected: request.service.name(),
            actual: enc_part_service.name(),
        });
    }

    let ticket_service = principal_from_parts(&kdc_rep.ticket.realm, &kdc_rep.ticket.sname)?;
    if !principal_matches(&ticket_service, &enc_part_service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: enc_part_service.name(),
            actual: ticket_service.name(),
        });
    }

    let ticket = encode("Ticket", &kdc_rep.ticket)?;
    Ok(AsRepSession {
        client,
        service: enc_part_service,
        session_key: encryption_key_from_rasn(&enc_part.key),
        ticket,
        ticket_flags: ticket_flags_to_bytes(&enc_part.flags),
        auth_time: system_time_from_kerberos_time(&enc_part.auth_time)?,
        start_time: system_time_from_kerberos_time(
            enc_part.start_time.as_ref().unwrap_or(&enc_part.auth_time),
        )?,
        end_time: system_time_from_kerberos_time(&enc_part.end_time)?,
        renew_till: enc_part
            .renew_till
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

/// Decode a KRB-ERROR and any METHOD-DATA preauthentication hints.
pub fn process_kdc_error(bytes: &[u8]) -> Result<KdcError, Error> {
    let krb_error = decode::<rasn_kerberos::KrbError>("KRB-ERROR", bytes)?;
    validate_integer("pvno", &krb_error.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_error.msg_type, KRB_ERROR_MSG_TYPE)?;

    let text = krb_error
        .e_text
        .as_ref()
        .map(kerberos_string_to_string)
        .transpose()?;
    let client = match (&krb_error.crealm, &krb_error.cname) {
        (Some(realm), Some(name)) => Some(principal_from_parts(realm, name)?),
        _ => None,
    };
    let service = principal_from_parts(&krb_error.realm, &krb_error.sname)?;
    let e_data = krb_error.e_data.as_ref().map(|data| data.as_ref().to_vec());
    let method_data = if krb_error.error_code == KDC_ERR_PREAUTH_REQUIRED {
        e_data
            .as_ref()
            .map(|data| decode::<rasn_kerberos::MethodData>("METHOD-DATA", data))
            .transpose()?
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let preauth_key_info = preauth_key_info_from_method_data(&method_data)?;

    Ok(KdcError {
        error_code: krb_error.error_code,
        text,
        client,
        service,
        e_data,
        method_data,
        preauth_key_info,
    })
}

/// Select a supported preauthentication key hint for the requested enctypes.
pub fn select_preauth_key_info(
    error: &KdcError,
    requested_etypes: &[i32],
) -> Result<PreauthKeyInfo, Error> {
    for etype in requested_etypes {
        if KerberosEtype::from_etype_id(*etype).is_none() {
            continue;
        }
        if let Some(info) = error
            .preauth_key_info
            .iter()
            .find(|info| info.etype == *etype)
        {
            return Ok(info.clone());
        }
    }

    if error.preauth_key_info.is_empty()
        && let Some(etype) = requested_etypes
            .iter()
            .copied()
            .find(|etype| KerberosEtype::from_etype_id(*etype).is_some())
    {
        return Ok(PreauthKeyInfo {
            etype,
            salt: None,
            s2kparams: None,
        });
    }

    Err(Error::NoSupportedPreauthEtype {
        requested: requested_etypes.to_vec(),
    })
}

/// Return the default Kerberos password salt for a principal.
pub fn default_password_salt(client: &Principal) -> String {
    let mut salt = client.realm.clone();
    for component in &client.components {
        salt.push_str(component);
    }
    salt
}

/// Derive a reply key from password credentials and a preauthentication hint.
pub fn derive_password_reply_key(
    client: &Principal,
    password: &[u8],
    key_info: &PreauthKeyInfo,
) -> Result<EncryptionKey, Error> {
    let etype = KerberosEtype::from_etype_id(key_info.etype)
        .ok_or(Error::UnsupportedEtype(key_info.etype))?;
    let salt = key_info
        .salt
        .clone()
        .unwrap_or_else(|| default_password_salt(client));
    let s2kparams = key_info
        .s2kparams
        .as_ref()
        .map(|bytes| encode_hex_lower(bytes))
        .unwrap_or_else(|| etype.default_s2kparams().to_owned());
    Ok(EncryptionKey {
        etype: key_info.etype,
        value: etype.string_to_key(password, salt.as_bytes(), &s2kparams)?,
    })
}

/// Select a reply key from a keytab using a preauthentication hint.
pub fn select_keytab_reply_key(
    keytab: &Keytab,
    client: &Principal,
    key_info: &PreauthKeyInfo,
) -> Result<(EncryptionKey, u32), Error> {
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (key, kvno) = keytab.find_key(&components, &client.realm, 0, key_info.etype)?;
    Ok((key.clone(), kvno))
}

/// Kerberos client exchange error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },

    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },

    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] std::str::Utf8Error),

    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),

    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },

    /// No ticket encryption types were requested.
    #[error("ticket request must request at least one encryption type")]
    EmptyEtypes,

    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),

    /// A key did not match the encrypted KDC reply data etype.
    #[error(
        "key etype {key_etype} does not match KDC-REP encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KDC-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// The KDC-REP client principal did not match the KDC-REQ.
    #[error("KDC-REP client {actual} does not match requested client {expected}")]
    ClientPrincipalMismatch {
        /// Expected request client.
        expected: String,
        /// Actual reply client.
        actual: String,
    },

    /// The KDC-REP service principal did not match the KDC-REQ.
    #[error("KDC-REP service {actual} does not match requested service {expected}")]
    ServicePrincipalMismatch {
        /// Expected request service.
        expected: String,
        /// Actual reply service.
        actual: String,
    },

    /// The KDC-REP nonce did not match the KDC-REQ nonce.
    #[error("KDC-REP nonce {actual} does not match KDC-REQ nonce {expected}")]
    NonceMismatch {
        /// Expected request nonce.
        expected: u32,
        /// Actual reply nonce.
        actual: u32,
    },

    /// A TGS referral chain exceeded the configured limit.
    #[error("TGS referral depth exceeded maximum {max}")]
    MaxReferralDepth {
        /// Maximum number of referrals followed.
        max: usize,
    },

    /// A TGS referral reply did not contain a usable `krbtgt/<realm>` service.
    #[error("invalid TGS referral ticket service: {service}")]
    InvalidReferralTicket {
        /// Referral ticket service name.
        service: String,
    },

    /// A renewal helper expected a `krbtgt/<realm>` TGT session.
    #[error("expected a TGT session, got service {service}")]
    InvalidTgtSession {
        /// Actual session service name.
        service: String,
    },

    /// A high-level client operation needs password/keytab credentials.
    #[cfg(feature = "tokio")]
    #[error("no password or keytab credentials are configured")]
    NoClientCredentials,

    /// A high-level client operation needs a current TGT.
    #[cfg(feature = "tokio")]
    #[error("no TGT session is available")]
    NoTgtSession,

    /// SPNEGO/GSSAPI token processing failed.
    #[cfg(feature = "spnego")]
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] crate::spnego::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    /// Keytab operation failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] crate::keytab::Error),

    /// Configuration parsing or lookup failed.
    #[error("config error: {0}")]
    Config(#[from] crate::config::Error),

    /// Credential cache operation failed.
    #[error("ccache error: {0}")]
    CCache(#[from] crate::ccache::Error),

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,

    /// The KDC returned an application-level error.
    #[error("KDC returned error code {}", .0.error_code)]
    Kdc(Box<KdcError>),

    /// No supported preauthentication encryption type was available.
    #[error("no supported preauthentication encryption type for requested list {requested:?}")]
    NoSupportedPreauthEtype {
        /// Requested encryption type ids.
        requested: Vec<i32>,
    },

    /// Tokio transport I/O failed.
    #[cfg(feature = "tokio")]
    #[error("KDC transport I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// A configured KDC endpoint could not be parsed.
    #[cfg(feature = "tokio")]
    #[error("invalid KDC endpoint: {0}")]
    InvalidKdcEndpoint(String),

    /// DNS resolver construction failed.
    #[cfg(feature = "tokio")]
    #[error("DNS resolver configuration failed: {0}")]
    DnsResolverConfig(String),

    /// DNS SRV KDC lookup failed.
    #[cfg(feature = "tokio")]
    #[error("DNS SRV lookup failed for {realm} over {protocol:?}: {message}")]
    DnsSrvLookup {
        /// Realm being discovered.
        realm: String,
        /// Requested wire protocol.
        protocol: KdcProtocol,
        /// Resolver error message.
        message: String,
    },

    /// No KDC endpoints were discovered for a realm.
    #[cfg(feature = "tokio")]
    #[error("no KDC endpoints discovered for {realm} over {protocol:?}")]
    NoKdcEndpoints {
        /// Realm being discovered.
        realm: String,
        /// Requested wire protocol.
        protocol: KdcProtocol,
    },

    /// All discovered KDC endpoint attempts failed.
    #[cfg(feature = "tokio")]
    #[error("all KDC endpoints for {realm} over {protocol:?} failed: {failures:?}")]
    KdcEndpointFailures {
        /// Realm being contacted.
        realm: String,
        /// Requested wire protocol.
        protocol: KdcProtocol,
        /// Per-endpoint failure messages.
        failures: Vec<String>,
    },

    /// Tokio transport exchange timed out.
    #[cfg(feature = "tokio")]
    #[error("KDC transport timed out after {0:?}")]
    TransportTimeout(Duration),

    /// UDP cannot carry the encoded request as one datagram.
    #[cfg(feature = "tokio")]
    #[error("KDC UDP request length {actual} exceeds datagram limit {limit}")]
    UdpRequestTooLarge {
        /// Encoded request byte length.
        actual: usize,
        /// Maximum UDP payload length.
        limit: usize,
    },

    /// TCP request length could not fit the RFC 4120 length prefix.
    #[cfg(feature = "tokio")]
    #[error("KDC TCP request length {actual} exceeds u32::MAX")]
    TcpRequestTooLarge {
        /// Encoded request byte length.
        actual: usize,
    },

    /// TCP response length exceeded the configured limit.
    #[cfg(feature = "tokio")]
    #[error("KDC TCP response length {actual} exceeds configured limit {limit}")]
    TcpResponseTooLarge {
        /// Response length from the TCP frame header.
        actual: u32,
        /// Maximum accepted response body length.
        limit: usize,
    },

    /// KDC returned no bytes.
    #[cfg(feature = "tokio")]
    #[error("KDC returned an empty response")]
    EmptyKdcResponse,

    /// KDC transport failed.
    #[error("KDC transport failed: {0}")]
    Transport(String),
}

fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    rasn::der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    rasn::der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

fn decrypt_encrypted_data(
    etype_id: i32,
    key: &[u8],
    ciphertext: &[u8],
    usage: u32,
) -> Result<Vec<u8>, Error> {
    let etype = KerberosEtype::from_etype_id(etype_id).ok_or(Error::UnsupportedEtype(etype_id))?;
    let plaintext = etype.decrypt_message(key, ciphertext, usage)?;
    Ok(crate::der::trim_zero_padded_der(&plaintext).to_vec())
}

fn password_preauth_request(
    client: Principal,
    password: &[u8],
    options: AsReqOptions,
    kdc_error_bytes: &[u8],
) -> Result<(BuiltAsReq, EncryptionKey), Error> {
    let error = process_kdc_error(kdc_error_bytes)?;
    if error.error_code != KDC_ERR_PREAUTH_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let key_info = select_preauth_key_info(&error, &options.etypes)?;
    let reply_key = derive_password_reply_key(&client, password, &key_info)?;
    let request = build_preauthenticated_tgt_as_req(client, options, &reply_key, None)?;
    Ok((request, reply_key))
}

fn password_initial_as_req(
    client: Principal,
    password: &[u8],
    options: AsReqOptions,
) -> Result<BuiltAsReq, Error> {
    let options = initial_preauth_probe_options(options);
    if options.assume_preauthentication {
        let key_info = assumed_preauth_key_info(&options.etypes)?;
        let reply_key = derive_password_reply_key(&client, password, &key_info)?;
        build_preauthenticated_tgt_as_req(client, options, &reply_key, None)
    } else {
        build_tgt_as_req(client, options)
    }
}

fn password_initial_as_rep_session(
    request: &BuiltAsReq,
    response: &[u8],
    client: &Principal,
    password: &[u8],
) -> Result<Option<AsRepSession>, Error> {
    let Some((etype, _)) = as_rep_reply_key_info(response) else {
        return Ok(None);
    };
    let key_info = PreauthKeyInfo {
        etype,
        salt: None,
        s2kparams: None,
    };
    let reply_key = derive_password_reply_key(client, password, &key_info)?;
    process_as_rep(request, response, &reply_key).map(Some)
}

fn keytab_preauth_request(
    client: Principal,
    keytab: &Keytab,
    options: AsReqOptions,
    kdc_error_bytes: &[u8],
) -> Result<(BuiltAsReq, EncryptionKey), Error> {
    let error = process_kdc_error(kdc_error_bytes)?;
    if error.error_code != KDC_ERR_PREAUTH_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let key_info = select_preauth_key_info(&error, &options.etypes)?;
    let (reply_key, kvno) = select_keytab_reply_key(keytab, &client, &key_info)?;
    let request = build_preauthenticated_tgt_as_req(client, options, &reply_key, Some(kvno))?;
    Ok((request, reply_key))
}

fn keytab_initial_as_req(
    client: Principal,
    keytab: &Keytab,
    options: AsReqOptions,
) -> Result<BuiltAsReq, Error> {
    let options = initial_preauth_probe_options(options);
    if options.assume_preauthentication {
        let (reply_key, kvno) = select_assumed_keytab_reply_key(keytab, &client, &options)?;
        build_preauthenticated_tgt_as_req(client, options, &reply_key, Some(kvno))
    } else {
        build_tgt_as_req(client, options)
    }
}

fn assumed_preauth_key_info(requested_etypes: &[i32]) -> Result<PreauthKeyInfo, Error> {
    requested_etypes
        .iter()
        .copied()
        .find(|etype| KerberosEtype::from_etype_id(*etype).is_some())
        .map(|etype| PreauthKeyInfo {
            etype,
            salt: None,
            s2kparams: None,
        })
        .ok_or_else(|| Error::NoSupportedPreauthEtype {
            requested: requested_etypes.to_vec(),
        })
}

fn select_assumed_keytab_reply_key(
    keytab: &Keytab,
    client: &Principal,
    options: &AsReqOptions,
) -> Result<(EncryptionKey, u32), Error> {
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    for etype in options
        .etypes
        .iter()
        .copied()
        .filter(|etype| KerberosEtype::from_etype_id(*etype).is_some())
    {
        match keytab.find_key(&components, &client.realm, 0, etype) {
            Ok((key, kvno)) => return Ok((key.clone(), kvno)),
            Err(crate::keytab::Error::NoMatchingKey { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::NoSupportedPreauthEtype {
        requested: options.etypes.clone(),
    })
}

fn keytab_initial_as_rep_session(
    request: &BuiltAsReq,
    response: &[u8],
    client: &Principal,
    keytab: &Keytab,
) -> Result<Option<AsRepSession>, Error> {
    let Some((etype, kvno)) = as_rep_reply_key_info(response) else {
        return Ok(None);
    };
    let (reply_key, _) =
        select_keytab_reply_key_for_etype(keytab, client, kvno.unwrap_or_default(), etype)?;
    process_as_rep(request, response, &reply_key).map(Some)
}

fn select_keytab_reply_key_for_etype(
    keytab: &Keytab,
    client: &Principal,
    kvno: u32,
    etype: i32,
) -> Result<(EncryptionKey, u32), Error> {
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (key, kvno) = keytab.find_key(&components, &client.realm, kvno, etype)?;
    Ok((key.clone(), kvno))
}

fn initial_preauth_probe_options(mut options: AsReqOptions) -> AsReqOptions {
    if !options
        .padata
        .iter()
        .any(|padata| padata.r#type == PA_REQ_ENC_PA_REP)
    {
        options.padata.push(rasn_kerberos::PaData {
            r#type: PA_REQ_ENC_PA_REP,
            value: Vec::new().into(),
        });
    }
    options
}

fn as_rep_reply_key_info(response: &[u8]) -> Option<(i32, Option<u32>)> {
    rasn::der::decode::<rasn_kerberos::AsRep>(response)
        .ok()
        .map(|as_rep| (as_rep.0.enc_part.etype, as_rep.0.enc_part.kvno))
}

fn decode_as_rep_enc_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    match decode::<rasn_kerberos::EncAsRepPart>("EncAsRepPart", bytes) {
        Ok(enc_part) => Ok(enc_part.0),
        Err(as_rep_error) => {
            // Some KDCs encode the shared encrypted KDC reply part with the
            // EncTgsRepPart application tag even when returning an AS-REP.
            decode::<rasn_kerberos::EncTgsRepPart>("EncTgsRepPart", bytes)
                .map(|enc_part| enc_part.0)
                .map_err(|_| as_rep_error)
        }
    }
}

fn decode_tgs_rep_enc_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    decode::<rasn_kerberos::EncTgsRepPart>("EncTgsRepPart", bytes).map(|enc_part| enc_part.0)
}

#[cfg(feature = "tokio")]
fn non_empty_kdc_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
    if response.is_empty() {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(response)
}

#[cfg(feature = "tokio")]
fn parse_kdc_endpoint(value: &str, default_port: u16) -> Result<(String, u16), Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidKdcEndpoint(value.to_owned()));
    }

    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        };
        if host.is_empty() {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        }
        let port = if let Some(port) = suffix.strip_prefix(':') {
            parse_kdc_port(value, port)?
        } else if suffix.is_empty() {
            default_port
        } else {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        };
        return Ok((host.to_owned(), port));
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.ends_with(':')
    {
        return Ok((host.to_owned(), parse_kdc_port(value, port)?));
    }

    if value.matches(':').count() == 1 {
        return Err(Error::InvalidKdcEndpoint(value.to_owned()));
    }

    Ok((value.to_owned(), default_port))
}

#[cfg(feature = "tokio")]
fn parse_kdc_port(endpoint: &str, port: &str) -> Result<u16, Error> {
    port.parse::<u16>()
        .map_err(|_| Error::InvalidKdcEndpoint(endpoint.to_owned()))
}

fn preauth_key_info_from_method_data(
    method_data: &[rasn_kerberos::PaData],
) -> Result<Vec<PreauthKeyInfo>, Error> {
    let mut infos = Vec::new();
    for padata in method_data
        .iter()
        .filter(|padata| padata.r#type == PA_ETYPE_INFO2)
    {
        let entries = decode::<rasn_kerberos::EtypeInfo2>("ETYPE-INFO2", padata.value.as_ref())?;
        for entry in entries {
            infos.push(PreauthKeyInfo {
                etype: entry.etype,
                salt: entry
                    .salt
                    .as_ref()
                    .map(kerberos_string_to_string)
                    .transpose()?,
                s2kparams: entry.s2kparams.map(|bytes| bytes.as_ref().to_vec()),
            });
        }
    }
    for padata in method_data
        .iter()
        .filter(|padata| padata.r#type == PA_ETYPE_INFO)
    {
        let entries = decode::<rasn_kerberos::EtypeInfo>("ETYPE-INFO", padata.value.as_ref())?;
        for entry in entries {
            infos.push(PreauthKeyInfo {
                etype: entry.etype,
                salt: entry
                    .salt
                    .as_ref()
                    .map(|salt| std::str::from_utf8(salt.as_ref()).map(str::to_owned))
                    .transpose()?,
                s2kparams: None,
            });
        }
    }
    Ok(infos)
}

fn current_preauth_time() -> Result<(SystemTime, u32), Error> {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TimeOverflow)?;
    Ok((
        UNIX_EPOCH + Duration::from_secs(elapsed.as_secs()),
        elapsed.subsec_micros(),
    ))
}

#[cfg(feature = "tokio")]
fn random_nonce() -> Result<u32, Error> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_integer(
    field: &'static str,
    actual: &rasn::types::Integer,
    expected: i32,
) -> Result<(), Error> {
    if actual != &rasn::types::Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn principal_to_rasn(value: &Principal) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: value.name_type,
        string: value
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<Principal, Error> {
    Ok(Principal {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn principal_matches(left: &Principal, right: &Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

fn is_tgt_principal(principal: &Principal) -> bool {
    principal
        .components
        .first()
        .is_some_and(|component| component.eq_ignore_ascii_case("krbtgt"))
        && principal.components.len() >= 2
}

fn tgt_realm(session: &AsRepSession) -> Option<String> {
    if is_tgt_principal(&session.service) {
        session.service.components.last().cloned()
    } else {
        None
    }
}

#[cfg(feature = "tokio")]
fn service_realm(config: &Config, service: &Principal) -> Option<String> {
    service
        .components
        .last()
        .and_then(|host| config.resolve_realm(host))
        .map(str::to_owned)
}

fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(std::str::from_utf8(value.as_bytes())?.to_owned())
}

fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

fn kdc_options_from_bits(bits: u32) -> rasn_kerberos::KdcOptions {
    rasn_kerberos::KdcOptions(rasn_kerberos::KerberosFlags::from_slice(
        &bits.to_be_bytes(),
    ))
}

fn request_kdc_option_bits(bits: u32, renew_lifetime: Option<Duration>) -> u32 {
    if renew_lifetime.is_some() {
        bits | KDC_OPTION_RENEWABLE
    } else {
        bits
    }
}

fn renewal_kdc_option_bits(bits: u32) -> u32 {
    bits | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW
}

fn zero_kerberos_flags() -> rasn_kerberos::KerberosFlags {
    rasn_kerberos::KerberosFlags::repeat(false, 32)
}

fn ticket_flags_to_bytes(flags: &rasn_kerberos::TicketFlags) -> [u8; 4] {
    let raw = flags.0.as_raw_slice();
    [
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ]
}

fn ccache_principal(value: &Principal) -> ccache::Principal {
    ccache::Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

#[cfg(feature = "tokio")]
fn same_ccache_client_identity(left: &ccache::Principal, right: &ccache::Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

#[cfg(feature = "tokio")]
fn client_principal_from_ccache(value: &ccache::Principal) -> Principal {
    Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

#[cfg(feature = "tokio")]
fn ccache_credential_session(credential: &ccache::Credential) -> AsRepSession {
    let auth_time = system_time_from_u32_seconds(credential.times.auth_time);
    let start_time = if credential.times.start_time == 0 {
        auth_time
    } else {
        system_time_from_u32_seconds(credential.times.start_time)
    };
    AsRepSession {
        client: client_principal_from_ccache(&credential.client),
        service: client_principal_from_ccache(&credential.server),
        session_key: EncryptionKey {
            etype: credential.key.etype,
            value: credential.key.value.clone(),
        },
        ticket: credential.ticket.clone(),
        ticket_flags: credential.ticket_flags,
        auth_time,
        start_time,
        end_time: system_time_from_u32_seconds(credential.times.end_time),
        renew_till: (credential.times.renew_till != 0)
            .then(|| system_time_from_u32_seconds(credential.times.renew_till)),
    }
}

#[cfg(feature = "tokio")]
fn system_time_from_u32_seconds(seconds: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds.into())
}

#[cfg(feature = "tokio")]
fn preferred_session_at(
    current: Option<AsRepSession>,
    candidate: AsRepSession,
    now: SystemTime,
) -> AsRepSession {
    match current {
        Some(current) if prefer_current_session_at(&current, &candidate, now) => current,
        _ => candidate,
    }
}

#[cfg(feature = "tokio")]
fn prefer_current_session_at(
    current: &AsRepSession,
    candidate: &AsRepSession,
    now: SystemTime,
) -> bool {
    match (
        session_valid_at(current, now),
        session_valid_at(candidate, now),
    ) {
        (true, false) => true,
        (false, true) => false,
        _ => current.end_time >= candidate.end_time,
    }
}

#[cfg(feature = "tokio")]
fn service_cache_key(service: &Principal) -> String {
    let mut key = service.realm.clone();
    for component in &service.components {
        key.push('\0');
        key.push_str(component);
    }
    key
}

#[cfg(feature = "tokio")]
fn session_valid_at(session: &AsRepSession, now: SystemTime) -> bool {
    session.start_time <= now && now < session.end_time
}

#[cfg(feature = "tokio")]
fn session_renewable_at(session: &AsRepSession, now: SystemTime) -> bool {
    session
        .renew_till
        .is_some_and(|renew_till| now < renew_till)
}

fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(seconds as u64, nanos))
            .ok_or(Error::TimeOverflow)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::new(seconds.unsigned_abs(), nanos))
            .ok_or(Error::TimeOverflow)
    }
}

fn kerberos_time_from_system_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, Error> {
    let (seconds, _) = unix_timestamp_parts(time)?;
    let utc =
        chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0).ok_or(Error::TimeOverflow)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOverflow)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

fn unix_timestamp_parts(time: SystemTime) -> Result<(i64, u32), Error> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok((
            duration
                .as_secs()
                .try_into()
                .map_err(|_| Error::TimeOverflow)?,
            duration.subsec_nanos(),
        )),
        Err(source) => {
            let duration = source.duration();
            let seconds: i64 = duration
                .as_secs()
                .try_into()
                .map_err(|_| Error::TimeOverflow)?;
            if duration.subsec_nanos() == 0 {
                return Ok((-seconds, 0));
            }

            let seconds = seconds.checked_add(1).ok_or(Error::TimeOverflow)?;
            Ok((-seconds, 1_000_000_000 - duration.subsec_nanos()))
        }
    }
}

fn system_time_to_u32_seconds(time: SystemTime) -> Result<u32, Error> {
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    if seconds < 0 || nanos != 0 {
        return Err(Error::TimeOverflow);
    }
    seconds.try_into().map_err(|_| Error::TimeOverflow)
}
