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
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ccache;
#[cfg(feature = "tokio")]
use crate::config::Config;
use crate::config::LibDefaults;
use crate::crypto::{KerberosEtype, Rc4HmacEtype, kerb_checksum_hmac_md5};
use crate::keytab::{EncryptionKey, Keytab};
#[cfg(feature = "tokio")]
use zeroize::Zeroizing;

mod kpasswd;
#[cfg(feature = "tokio")]
mod transport;
pub use self::kpasswd::{
    BuiltKpasswdRequest, KpasswdRequestOptions, VerifiedKpasswdApRep, build_kpasswd_request,
    build_kpasswd_request_with_confounders, verify_kpasswd_ap_rep,
};
#[cfg(feature = "tokio")]
pub use self::transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, TokioKdcTransport};

const KRB5_PVNO: i32 = 5;
const KRB_NT_PRINCIPAL: i32 = 1;
const KRB_NT_SRV_INST: i32 = 2;
const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_TKT_ENCTYPES: &[i32] = &[20, 19, 18, 17];
const DEFAULT_TGS_ENCTYPES: &[i32] = DEFAULT_TKT_ENCTYPES;
#[cfg(feature = "tokio")]
const KRB5CCNAME_ENV: &str = "KRB5CCNAME";
#[cfg(feature = "tokio")]
const KRB5_CLIENT_KTNAME_ENV: &str = "KRB5_CLIENT_KTNAME";
#[cfg(feature = "tokio")]
const SESSION_REFRESH_DIVISOR: u32 = 6;

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

/// PA-FX-FAST padata type used to signal FAST negotiation support.
pub const PA_FX_FAST: i32 = 136;

/// PA-PAC-OPTIONS preauthentication type used by MS-KILE.
pub const PA_PAC_OPTIONS: i32 = 167;

/// PA-FOR-USER padata type used by S4U2Self.
pub const PA_FOR_USER: i32 = 129;

/// KDC error code for additional preauthentication required.
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
/// KDC error code indicating the client should retry over TCP.
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// Key usage for AS-REQ encrypted timestamp preauthentication.
pub const AS_REQ_PA_ENC_TIMESTAMP_USAGE: u32 = 1;

/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = crate::kdc_rep::AS_REP_ENCPART_USAGE;

/// Key usage for PA-REQ-ENC-PA-REP checksums over the original AS-REQ.
pub const AS_REQ_CHECKSUM_USAGE: u32 = 56;

/// Key usage for the TGS-REQ request-body checksum inside the authenticator.
pub const TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE: u32 = 6;

/// Key usage for the PA-TGS-REQ AP-REQ authenticator.
pub const TGS_REQ_AUTHENTICATOR_USAGE: u32 = 7;

/// Key usage for normal AP-REQ authenticators.
pub const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;

/// Key usage for AP-REP encrypted parts.
pub const AP_REP_ENCPART_USAGE: u32 = 12;

/// Key usage for TGS-REP encrypted parts when encrypted with the TGT session key.
pub const TGS_REP_ENCPART_SESSION_KEY_USAGE: u32 =
    crate::kdc_rep::TGS_REP_ENCPART_SESSION_KEY_USAGE;

/// Key usage/message type for PA-FOR-USER checksums.
pub const PA_FOR_USER_CHECKSUM_USAGE: u32 = 17;

/// Raw PAC option mask for `claims`.
pub const PAC_OPTION_CLAIMS: u32 = 0x8000_0000;

/// Raw PAC option mask for `branch-aware`.
pub const PAC_OPTION_BRANCH_AWARE: u32 = 0x4000_0000;

/// Raw PAC option mask for `forward-to-full-DC`.
pub const PAC_OPTION_FORWARD_TO_FULL_DC: u32 = 0x2000_0000;

/// Raw PAC option mask for `resource-based constrained delegation`.
pub const PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION: u32 = 0x1000_0000;

/// Ticket flag bit indicating the AS-REP carries encrypted padata.
pub const TICKET_FLAG_ENC_PA_REP: u32 = 0x0001_0000;

/// Raw KDC option mask for `renewable` in RFC 4120 bit-string order.
pub const KDC_OPTION_RENEWABLE: u32 = 0x0080_0000;

/// Raw KDC option mask for `canonicalize` in RFC 4120 bit-string order.
pub const KDC_OPTION_CANONICALIZE: u32 = 0x0001_0000;

/// Raw KDC option mask for `cname-in-addl-tkt` in RFC 4120 bit-string order.
pub const KDC_OPTION_CNAME_IN_ADDL_TKT: u32 = 0x0002_0000;

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

    /// Parse a single-component user principal in `user@REALM` form.
    ///
    /// Separator characters may be escaped with `\`, for example
    /// `user\@name@REALM` parses as user component `user@name`.
    pub fn parse_user(value: impl AsRef<str>) -> Result<Self, Error> {
        let value = value.as_ref();
        let (name, realm) = parse_name_and_realm(value)?;
        let components = parse_principal_components(value, name)?;
        if components.len() != 1 {
            return Err(invalid_principal_name(
                value,
                "user principal must contain exactly one name component",
            ));
        }
        Ok(Self::user(realm, components.into_iter().next().unwrap()))
    }

    /// Parse a host service principal in `service/host@REALM` form.
    ///
    /// This creates a name type 2 service principal with components
    /// `[service, host]`, matching the host-based service shape used by
    /// native GSSAPI.
    pub fn parse_service(value: impl AsRef<str>) -> Result<Self, Error> {
        let value = value.as_ref();
        let (name, realm) = parse_name_and_realm(value)?;
        let components = parse_principal_components(value, name)?;
        if components.len() != 2 {
            return Err(invalid_principal_name(
                value,
                "service principal must contain service and host components",
            ));
        }
        Ok(Self::new(realm, KRB_NT_SRV_INST, components))
    }

    /// Create a host-based service principal with an empty realm.
    ///
    /// High-level clients resolve the empty service realm from
    /// `[domain_realm]` and then from the client realm.
    pub fn host_based_service(
        service: impl AsRef<str>,
        host: impl AsRef<str>,
    ) -> Result<Self, Error> {
        host_based_service_principal(service.as_ref(), host.as_ref(), "")
    }

    /// Create a host-based service principal in a specific realm.
    pub fn host_based_service_in_realm(
        service: impl AsRef<str>,
        host: impl AsRef<str>,
        realm: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let service = service.as_ref();
        let host = host.as_ref();
        let realm = realm.as_ref();
        if realm.is_empty() {
            return Err(invalid_principal_name(
                realm,
                "host-based service realm is empty",
            ));
        }
        host_based_service_principal(service, host, realm)
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

fn host_based_service_principal(
    service: &str,
    host: &str,
    realm: &str,
) -> Result<Principal, Error> {
    if service.is_empty() {
        return Err(invalid_principal_name(
            service,
            "host-based service name is empty",
        ));
    }
    if host.is_empty() {
        return Err(invalid_principal_name(
            host,
            "host-based service host is empty",
        ));
    }
    Ok(Principal::new(
        realm,
        KRB_NT_SRV_INST,
        [service.to_owned(), host.to_owned()],
    ))
}

fn parse_name_and_realm(value: &str) -> Result<(&str, String), Error> {
    if value.is_empty() {
        return Err(invalid_principal_name(value, "principal name is empty"));
    }
    let separators = unescaped_separator_indices(value, '@');
    let [separator] = separators.as_slice() else {
        return Err(invalid_principal_name(
            value,
            if separators.is_empty() {
                "principal realm separator is missing"
            } else {
                "principal contains more than one unescaped realm separator"
            },
        ));
    };
    let (name, realm) = value.split_at(*separator);
    let realm = &realm['@'.len_utf8()..];
    if name.is_empty() {
        return Err(invalid_principal_name(
            value,
            "principal name component is empty",
        ));
    }
    let realm = unescape_principal_component(value, realm)?;
    if realm.is_empty() {
        return Err(invalid_principal_name(value, "principal realm is empty"));
    }
    Ok((name, realm))
}

fn parse_principal_components(value: &str, name: &str) -> Result<Vec<String>, Error> {
    let mut components = Vec::new();
    let mut start = 0usize;
    for separator in unescaped_separator_indices(name, '/') {
        components.push(unescape_principal_component(
            value,
            &name[start..separator],
        )?);
        start = separator + '/'.len_utf8();
    }
    components.push(unescape_principal_component(value, &name[start..])?);
    if components.iter().any(String::is_empty) {
        return Err(invalid_principal_name(
            value,
            "principal contains an empty name component",
        ));
    }
    Ok(components)
}

fn unescaped_separator_indices(value: &str, separator: char) -> Vec<usize> {
    let mut escaped = false;
    let mut positions = Vec::new();
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == separator {
            positions.push(index);
        }
    }
    positions
}

fn unescape_principal_component(value: &str, component: &str) -> Result<String, Error> {
    let mut escaped = false;
    let mut out = String::with_capacity(component.len());
    for ch in component.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return Err(invalid_principal_name(
            value,
            "principal contains a trailing escape character",
        ));
    }
    Ok(out)
}

fn invalid_principal_name(value: &str, reason: &'static str) -> Error {
    Error::InvalidPrincipalName {
        value: value.to_owned(),
        reason,
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
    /// Advertise support for AS-REP encrypted padata negotiation.
    pub fast_negotiation: bool,
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
            fast_negotiation: true,
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
        if defaults.canonicalize {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
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

    /// Configure whether high-level AS login advertises PA-REQ-ENC-PA-REP.
    pub fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
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
    /// Additional TGS padata appended after PA-TGS-REQ.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Additional tickets included in the TGS request body.
    pub additional_tickets: Vec<rasn_kerberos::Ticket>,
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
            padata: Vec::new(),
            additional_tickets: Vec::new(),
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
        if defaults.canonicalize {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
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

    /// Add additional TGS padata.
    pub fn with_padata(mut self, padata: impl Into<Vec<rasn_kerberos::PaData>>) -> Self {
        self.padata = padata.into();
        self
    }

    /// Add additional tickets to the TGS request body.
    pub fn with_additional_tickets(
        mut self,
        additional_tickets: impl Into<Vec<rasn_kerberos::Ticket>>,
    ) -> Self {
        self.additional_tickets = additional_tickets.into();
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
    /// Expected client principal in the KDC reply.
    ///
    /// This is normally the same principal that authenticated the TGS-REQ, but
    /// S4U2Self replies carry the impersonated user as the client.
    pub client: Principal,
    /// Requested service principal.
    pub service: Principal,
    /// Realm contacted for the TGS exchange.
    pub kdc_realm: String,
    /// Request nonce.
    pub nonce: u32,
}

/// Options for constructing a client AP-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApReqOptions {
    /// Raw AP option bit string.
    pub ap_option_bits: u32,
    /// Optional authenticator checksum.
    pub checksum: Option<rasn_kerberos::Checksum>,
    /// Optional client-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    pub sequence_number: Option<u32>,
}

impl ApReqOptions {
    /// Construct AP-REQ options with no flags or optional authenticator fields.
    pub fn new() -> Self {
        Self {
            ap_option_bits: 0,
            checksum: None,
            subkey: None,
            sequence_number: None,
        }
    }

    /// Override AP-REQ option bits.
    pub fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
        self
    }

    /// Set or clear the authenticator checksum.
    pub fn with_checksum(mut self, checksum: Option<rasn_kerberos::Checksum>) -> Self {
        self.checksum = checksum;
        self
    }

    /// Set or clear the client-selected subkey.
    pub fn with_subkey(mut self, subkey: Option<EncryptionKey>) -> Self {
        self.subkey = subkey;
        self
    }

    /// Set or clear the client sequence number.
    pub fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self {
        self.sequence_number = sequence_number;
        self
    }
}

impl Default for ApReqOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Built client AP-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltApReq {
    /// ASN.1 AP-REQ message.
    pub message: rasn_kerberos::ApReq,
    /// DER-encoded AP-REQ bytes.
    pub der: Vec<u8>,
    /// Client principal placed in the authenticator.
    pub client: Principal,
    /// Service principal from the ticket.
    pub service: Principal,
    /// Service-ticket session key used to encrypt the authenticator.
    pub session_key: EncryptionKey,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional client sequence number supplied in the authenticator.
    pub sequence_number: Option<u32>,
    /// Optional client-selected subkey supplied in the authenticator.
    pub subkey: Option<EncryptionKey>,
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
    /// Session key expiration time, when supplied.
    pub key_expiration: Option<SystemTime>,
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

/// Result of a referral-following TGS exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferralTgsResult {
    /// Final service ticket.
    pub ticket: TgsRepSession,
    /// Intermediate referral TGTs acquired while reaching the service realm.
    pub referral_tgts: Vec<AsRepSession>,
}

/// Runtime-neutral boundary for KDC request/response transport.
pub trait KdcTransport {
    /// Send an encoded KDC request and return the encoded KDC response.
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Parsed KRB-ERROR returned by a KDC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdcError {
    /// Client time, when present.
    pub ctime: Option<SystemTime>,
    /// Client microseconds, when present.
    pub cusec: Option<u32>,
    /// KDC/server time.
    pub stime: SystemTime,
    /// KDC/server microseconds.
    pub susec: u32,
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

/// Client configuration and runtime-state diagnostics.
///
/// This is the structured equivalent of gokrb5's client diagnostics output:
/// callers can inspect local credential state, KDC discovery results, and
/// configuration/keytab mismatches without parsing a formatted text block.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
pub struct TokioClientDiagnostics {
    /// Client principal name.
    pub client: String,
    /// Client realm.
    pub realm: String,
    /// Selected high-level transport protocol.
    pub protocol: String,
    /// Configured credential source: `password`, `keytab`, or `none`.
    pub credential_source: String,
    /// Whether the client currently holds a TGT session.
    pub has_tgt: bool,
    /// Number of cached TGT sessions.
    pub tgt_session_count: usize,
    /// Number of cached service tickets.
    pub service_ticket_cache_count: usize,
    /// Configured default ticket enctype IDs.
    pub default_tkt_enctypes: Vec<i32>,
    /// Configured preferred preauthentication type IDs.
    pub preferred_preauth_types: Vec<i32>,
    /// Key encryption type IDs present for the client realm in the keytab.
    pub keytab_enctypes: Vec<i32>,
    /// UDP KDC endpoints discovered from config or DNS.
    #[cfg_attr(feature = "serde", serde(rename = "UDPKDCs"))]
    pub udp_kdcs: Vec<String>,
    /// TCP KDC endpoints discovered from config or DNS.
    #[cfg_attr(feature = "serde", serde(rename = "TCPKDCs"))]
    pub tcp_kdcs: Vec<String>,
    /// Configuration and discovery errors found by diagnostics.
    pub errors: Vec<String>,
}

#[cfg(feature = "tokio")]
impl TokioClientDiagnostics {
    /// Whether diagnostics found no errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Counts of unusable sessions removed from a Tokio client cache.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
pub struct PrunedSessions {
    /// Whether the primary TGT was removed.
    pub primary_tgt: bool,
    /// Number of realm-keyed TGT sessions removed.
    pub tgt_sessions: usize,
    /// Number of service tickets removed.
    pub service_tickets: usize,
}

#[cfg(feature = "tokio")]
impl PrunedSessions {
    /// Whether no sessions were removed.
    pub fn is_empty(&self) -> bool {
        !self.primary_tgt && self.tgt_sessions == 0 && self.service_tickets == 0
    }
}

/// Handle for a background Tokio TGT auto-renewal task.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct TokioClientAutoRenewal {
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "tokio")]
impl TokioClientAutoRenewal {
    /// Request cancellation of the background renewal task.
    pub fn abort(&self) {
        self.handle.abort();
    }

    /// Whether the background task has finished.
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

#[cfg(feature = "tokio")]
impl Drop for TokioClientAutoRenewal {
    fn drop(&mut self) {
        self.handle.abort();
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
    tgt_sessions: BTreeMap<String, AsRepSession>,
    service_tickets: BTreeMap<String, TgsRepSession>,
    assume_preauthentication: bool,
    fast_negotiation: bool,
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
            .field("tgt_sessions", &self.tgt_sessions.len())
            .field("cached_service_tickets", &self.service_tickets.len())
            .field("assume_preauthentication", &self.assume_preauthentication)
            .field("fast_negotiation", &self.fast_negotiation)
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

    /// Create a keytab-backed client by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    pub fn with_keytab_name(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab_name: impl AsRef<str>,
    ) -> Result<Self, Error> {
        Ok(Self::with_keytab(
            config,
            protocol,
            client,
            Keytab::load_name(keytab_name)?,
        ))
    }

    /// Create a keytab-backed client from `config.libdefaults.default_client_keytab_name`.
    pub fn with_client_keytab_from_config(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab_name = config.libdefaults.default_client_keytab_name.clone();
        Self::with_keytab_name(config, protocol, client, keytab_name)
    }

    /// Create a keytab-backed client from the default client keytab.
    ///
    /// `KRB5_CLIENT_KTNAME` takes precedence when set. Otherwise this falls
    /// back to `config.libdefaults.default_client_keytab_name`.
    pub fn with_client_keytab_from_default(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab_name = default_client_keytab_name(&config)?;
        Self::with_keytab_name(config, protocol, client, keytab_name)
    }

    /// Create a keytab-backed client by loading the file keytab named by `KRB5_CLIENT_KTNAME`.
    pub fn with_client_keytab_from_env(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab_name =
            std::env::var(KRB5_CLIENT_KTNAME_ENV).map_err(Error::DefaultClientKeytabName)?;
        Self::with_keytab_name(config, protocol, client, keytab_name)
    }

    /// Create a keytab-backed client by loading the file keytab named by `KRB5_KTNAME`.
    pub fn with_keytab_from_env(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        Ok(Self::with_keytab(
            config,
            protocol,
            client,
            Keytab::load_from_env()?,
        ))
    }

    /// Attach or replace password credentials on an existing client.
    ///
    /// This is useful when starting from a ccache-loaded client and keeping
    /// live credentials available for later refreshes.
    pub fn with_password_credential(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.credentials = Some(TokioClientCredentials::Password(Zeroizing::new(
            password.into(),
        )));
        self
    }

    /// Attach or replace keytab credentials on an existing client.
    ///
    /// This is useful when starting from a ccache-loaded client and keeping
    /// live credentials available for later refreshes.
    pub fn with_keytab_credential(mut self, keytab: Keytab) -> Self {
        self.credentials = Some(TokioClientCredentials::Keytab(keytab));
        self
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
                let _ = kerberos.cache_tgt_session_at(session, now);
            } else {
                kerberos.cache_service_ticket(session);
            }
        }
        kerberos
    }

    /// Create a cache-only client by loading a ccache name.
    ///
    /// Bare paths, `FILE:path`, `WRFILE:path`, and MIT `DIR:` collection names
    /// are supported by the ccache module. Other credential cache stores are
    /// rejected explicitly.
    pub fn from_ccache_name(
        config: Config,
        protocol: KdcProtocol,
        cache_name: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let cache = ccache::CCache::load_name(cache_name)?;
        Ok(Self::from_ccache(config, protocol, &cache))
    }

    /// Create a cache-only client from `config.libdefaults.default_ccache_name`.
    pub fn from_default_ccache_name(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache_name = configured_default_ccache_name(&config)?;
        Self::from_ccache_name(config, protocol, cache_name)
    }

    /// Create a cache-only client from the default credential cache.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    pub fn from_default_ccache(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache_name = default_ccache_name(&config)?;
        Self::from_ccache_name(config, protocol, cache_name)
    }

    /// Create a cache-only client by loading the file ccache named by `KRB5CCNAME`.
    pub fn from_ccache_env(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache = ccache::CCache::load_from_env()?;
        Ok(Self::from_ccache(config, protocol, &cache))
    }

    /// Create a cache-only client from a known TGT session.
    pub fn from_tgt_session(config: Config, protocol: KdcProtocol, tgt: AsRepSession) -> Self {
        let mut kerberos = Self::new(config, protocol, tgt.client.clone(), None);
        let _ = kerberos.cache_tgt_session(tgt);
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

    /// Save current TGT and service-ticket state to a fresh ccache name.
    pub fn save_ccache_name(&self, cache_name: impl AsRef<str>) -> Result<(), Error> {
        self.to_ccache()?.save_name(cache_name)?;
        Ok(())
    }

    /// Save current TGT and service-ticket state to `config.libdefaults.default_ccache_name`.
    pub fn save_default_ccache_name(&self) -> Result<(), Error> {
        self.save_ccache_name(configured_default_ccache_name(&self.config)?)
    }

    /// Save current TGT and service-ticket state to the default credential cache.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    pub fn save_default_ccache(&self) -> Result<(), Error> {
        self.save_ccache_name(default_ccache_name(&self.config)?)
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

    /// Load an existing ccache name, update this client's entries, and save it.
    ///
    /// Missing files are created. Existing X-CACHECONF metadata and entries for
    /// other clients are preserved.
    pub fn update_ccache_name(&self, cache_name: impl AsRef<str>) -> Result<(), Error> {
        let path = ccache::CCache::file_path_from_cache_name(cache_name.as_ref())?;
        self.update_ccache_file(path)
    }

    /// Update the ccache named by `config.libdefaults.default_ccache_name`.
    pub fn update_default_ccache_name(&self) -> Result<(), Error> {
        self.update_ccache_name(configured_default_ccache_name(&self.config)?)
    }

    /// Update the default credential cache.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    pub fn update_default_ccache(&self) -> Result<(), Error> {
        self.update_ccache_name(default_ccache_name(&self.config)?)
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
            tgt_sessions: BTreeMap::new(),
            service_tickets: BTreeMap::new(),
            assume_preauthentication: false,
            fast_negotiation: true,
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

    /// Configure whether AS login advertises PA-REQ-ENC-PA-REP.
    pub fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
        self
    }

    /// Spawn a background task that refreshes the primary TGT before expiry.
    ///
    /// Dropping or aborting the returned handle cancels the task. The client is
    /// shared explicitly so callers control the synchronization boundary.
    pub fn spawn_auto_renewal(
        client: std::sync::Arc<tokio::sync::Mutex<Self>>,
    ) -> TokioClientAutoRenewal {
        Self::spawn_auto_renewal_with_retry(client, Duration::from_secs(60))
    }

    /// Spawn a background TGT refresh task with a custom retry delay for errors.
    pub fn spawn_auto_renewal_with_retry(
        client: std::sync::Arc<tokio::sync::Mutex<Self>>,
        retry_delay: Duration,
    ) -> TokioClientAutoRenewal {
        let retry_delay = retry_delay.max(Duration::from_millis(1));
        let handle = tokio::spawn(async move {
            loop {
                let delay = {
                    let client = client.lock().await;
                    client
                        .tgt
                        .as_ref()
                        .map(|tgt| session_refresh_delay_at(tgt, SystemTime::now()))
                        .unwrap_or(Duration::ZERO)
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }

                let mut client = client.lock().await;
                if client.credentials.is_none() && client.tgt.is_none() {
                    return;
                }
                if client.refresh_tgt_if_needed().await.is_err() {
                    drop(client);
                    tokio::time::sleep(retry_delay).await;
                }
            }
        });
        TokioClientAutoRenewal { handle }
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

    /// Validate that the client has enough local state for KDC operations.
    pub fn validate_configuration(&self) -> Result<(), Error> {
        if self.client.components.is_empty()
            || self
                .client
                .components
                .iter()
                .any(|component| component.is_empty())
        {
            return Err(Error::MissingClientName);
        }
        if self.client.realm.is_empty() {
            return Err(Error::MissingClientRealm);
        }
        if self.credentials.is_none() && self.tgt.is_none() {
            return Err(Error::NoClientCredentials);
        }
        if !self.config.libdefaults.dns_lookup_kdc {
            let realm_entry =
                self.config
                    .realm(&self.client.realm)
                    .ok_or_else(|| Error::NoConfiguredKdc {
                        realm: self.client.realm.clone(),
                    })?;
            if realm_entry.kdc.is_empty() {
                return Err(Error::NoConfiguredKdc {
                    realm: self.client.realm.clone(),
                });
            }
        }
        Ok(())
    }

    /// Whether the client has enough local state for KDC operations.
    pub fn is_configured(&self) -> bool {
        self.validate_configuration().is_ok()
    }

    /// Run structured client diagnostics.
    pub async fn diagnostics(&self) -> TokioClientDiagnostics {
        let mut errors = Vec::new();
        if let Err(error) = self.validate_configuration() {
            errors.push(error.to_string());
        }

        let keytab_enctypes = match self.credentials.as_ref() {
            Some(TokioClientCredentials::Keytab(keytab)) => {
                let enctypes = keytab_realm_enctypes(keytab, &self.client.realm);
                record_keytab_enctype_diagnostics(
                    &mut errors,
                    &enctypes,
                    &self.config.libdefaults.default_tkt_enctype_ids,
                    "default_tkt_enctypes",
                );
                record_keytab_enctype_diagnostics(
                    &mut errors,
                    &enctypes,
                    &self.config.libdefaults.preferred_preauth_types,
                    "preferred_preauth_types",
                );
                enctypes
            }
            _ => Vec::new(),
        };

        let udp_kdcs = self
            .diagnostic_kdc_endpoints(KdcProtocol::Udp, &mut errors)
            .await;
        let tcp_kdcs = self
            .diagnostic_kdc_endpoints(KdcProtocol::Tcp, &mut errors)
            .await;

        TokioClientDiagnostics {
            client: self.client.name(),
            realm: self.client.realm.clone(),
            protocol: protocol_label(self.protocol).to_owned(),
            credential_source: credential_source(self.credentials.as_ref()).to_owned(),
            has_tgt: self.tgt.is_some(),
            tgt_session_count: self.tgt_sessions.len(),
            service_ticket_cache_count: self.service_tickets.len(),
            default_tkt_enctypes: self.config.libdefaults.default_tkt_enctype_ids.clone(),
            preferred_preauth_types: self.config.libdefaults.preferred_preauth_types.clone(),
            keytab_enctypes,
            udp_kdcs,
            tcp_kdcs,
            errors,
        }
    }

    /// Run diagnostics and return pretty-printed JSON.
    #[cfg(feature = "serde")]
    pub async fn diagnostics_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.diagnostics().await)
    }

    /// Whether AS login sends PA-ENC-TIMESTAMP in the first AS-REQ.
    pub fn assume_preauthentication(&self) -> bool {
        self.assume_preauthentication
    }

    /// Whether AS login advertises PA-REQ-ENC-PA-REP.
    pub fn fast_negotiation(&self) -> bool {
        self.fast_negotiation
    }

    /// Current TGT session, when logged in or loaded from cache.
    pub fn tgt_session(&self) -> Option<&AsRepSession> {
        self.tgt.as_ref()
    }

    /// Whether the primary TGT is missing, expired, or inside the refresh window.
    pub fn tgt_refresh_due(&self) -> bool {
        self.tgt
            .as_ref()
            .is_none_or(|tgt| session_refresh_due_at(tgt, SystemTime::now()))
    }

    /// Number of cached TGT sessions keyed by target realm.
    pub fn tgt_session_count(&self) -> usize {
        self.tgt_sessions.len()
    }

    /// Cached TGT session for a target realm, when present.
    pub fn tgt_session_for_realm(&self, realm: &str) -> Option<&AsRepSession> {
        self.tgt_sessions.get(realm)
    }

    /// Remove a cached TGT session for a target realm.
    pub fn remove_tgt_session_for_realm(&mut self, realm: &str) -> Option<AsRepSession> {
        let removed = self.tgt_sessions.remove(realm);
        if realm == self.client.realm {
            let primary = self.tgt.take();
            return removed.or(primary);
        }
        removed
    }

    /// Number of cached service tickets.
    pub fn cached_service_ticket_count(&self) -> usize {
        self.service_tickets.len()
    }

    /// Clear cached service tickets without dropping the TGT.
    pub fn clear_service_ticket_cache(&mut self) {
        self.service_tickets.clear();
    }

    /// Return a currently valid cached service ticket without contacting a KDC.
    pub fn cached_service_ticket(&self, service: Principal) -> Option<TgsRepSession> {
        let service = self.resolve_service_principal(service);
        let key = service_cache_key(&service);
        let mut ticket = self.service_tickets.get(&key)?.clone();
        if !session_valid_at(&ticket, SystemTime::now()) {
            return None;
        }
        ticket.service = service;
        Some(ticket)
    }

    /// Remove a cached service ticket without dropping the TGT.
    pub fn remove_cached_service_ticket(&mut self, service: Principal) -> Option<TgsRepSession> {
        let service = self.resolve_service_principal(service);
        let key = service_cache_key(&service);
        self.service_tickets.remove(&key)
    }

    /// Drop expired, non-renewable TGT and service-ticket sessions from local caches.
    pub fn prune_unusable_sessions(&mut self) -> PrunedSessions {
        self.prune_unusable_sessions_at(SystemTime::now())
    }

    fn prune_unusable_sessions_at(&mut self, now: SystemTime) -> PrunedSessions {
        let primary_tgt = self
            .tgt
            .as_ref()
            .is_some_and(|tgt| !session_usable_at(tgt, now));
        if primary_tgt {
            self.tgt = None;
        }

        let tgt_session_count = self.tgt_sessions.len();
        self.tgt_sessions
            .retain(|_, session| session_usable_at(session, now));

        let service_ticket_count = self.service_tickets.len();
        self.service_tickets
            .retain(|_, session| session_usable_at(session, now));

        PrunedSessions {
            primary_tgt,
            tgt_sessions: tgt_session_count - self.tgt_sessions.len(),
            service_tickets: service_ticket_count - self.service_tickets.len(),
        }
    }

    /// Drop live credentials, the TGT session, and all cached service tickets.
    pub fn destroy(&mut self) {
        self.credentials = None;
        self.tgt = None;
        self.tgt_sessions.clear();
        self.service_tickets.clear();
    }

    /// Return public TGT session metadata as pretty-printed JSON.
    #[cfg(feature = "serde")]
    pub fn sessions_json(&self) -> Result<String, serde_json::Error> {
        let sessions = self
            .tgt_sessions
            .values()
            .map(session_json_entry)
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&sessions)
    }

    /// Return public service-ticket cache metadata as pretty-printed JSON.
    #[cfg(feature = "serde")]
    pub fn service_ticket_cache_json(&self) -> Result<String, serde_json::Error> {
        let tickets = self
            .service_tickets
            .values()
            .map(service_ticket_json_entry)
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&tickets)
    }

    /// Insert or replace a service ticket in the cache.
    pub fn cache_service_ticket(&mut self, ticket: TgsRepSession) {
        let key = service_cache_key(&ticket.service);
        let ticket =
            preferred_session_at(self.service_tickets.remove(&key), ticket, SystemTime::now());
        self.service_tickets.insert(key, ticket);
    }

    /// Insert or replace a TGT session in the realm-keyed session cache.
    pub fn cache_tgt_session(&mut self, tgt: AsRepSession) -> Result<(), Error> {
        self.cache_tgt_session_at(tgt, SystemTime::now())
    }

    fn cache_tgt_session_at(&mut self, tgt: AsRepSession, now: SystemTime) -> Result<(), Error> {
        let realm = tgt_realm(&tgt).ok_or_else(|| Error::InvalidTgtSession {
            service: tgt.service.name(),
        })?;
        let selected = preferred_session_at(self.tgt_sessions.remove(&realm), tgt, now);
        if realm == self.client.realm {
            let primary = preferred_session_at(self.tgt.take(), selected, now);
            self.tgt = Some(primary.clone());
            self.tgt_sessions.insert(realm, primary);
        } else {
            self.tgt_sessions.insert(realm, selected);
        }
        Ok(())
    }

    /// Ensure this client has a valid TGT, reusing an existing TGT when possible.
    pub async fn affirm_login(&mut self) -> Result<&AsRepSession, Error> {
        if let Some(tgt) = self.tgt.clone() {
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) {
                return Ok(self.tgt.as_ref().expect("TGT was just checked"));
            }
            if session_renewable_at(&tgt, now) {
                return self.renew_tgt().await;
            }
        }

        self.login().await
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

        self.tgt_sessions.clear();
        self.cache_tgt_session(session)?;
        self.service_tickets.clear();
        Ok(self.tgt.as_ref().expect("TGT was just inserted"))
    }

    /// Renew the current TGT explicitly.
    pub async fn renew_tgt(&mut self) -> Result<&AsRepSession, Error> {
        let realm = self.client.realm.clone();
        self.renew_tgt_session_for_realm(&realm).await?;
        Ok(self.tgt.as_ref().expect("TGT was just inserted"))
    }

    /// Renew a cached TGT session for a target realm.
    pub async fn renew_tgt_session_for_realm(
        &mut self,
        realm: &str,
    ) -> Result<AsRepSession, Error> {
        let tgt = if realm == self.client.realm {
            self.tgt
                .clone()
                .or_else(|| self.tgt_sessions.get(realm).cloned())
        } else {
            self.tgt_sessions.get(realm).cloned()
        }
        .ok_or(Error::NoTgtSession)?;
        let renewed = self
            .transport
            .renew_tgt_with_config(&self.config, self.protocol, &tgt, self.tgs_req_options()?)
            .await?;
        let renewed_realm = tgt_realm(&renewed).ok_or_else(|| Error::InvalidTgtSession {
            service: renewed.service.name(),
        })?;
        if renewed_realm == self.client.realm {
            self.tgt = Some(renewed.clone());
            self.service_tickets.clear();
        }
        self.tgt_sessions.insert(renewed_realm, renewed.clone());
        Ok(renewed)
    }

    /// Refresh the primary TGT if it is missing, expired, or inside the refresh window.
    pub async fn refresh_tgt_if_needed(&mut self) -> Result<&AsRepSession, Error> {
        let _ = self.ensure_tgt().await?;
        self.tgt.as_ref().ok_or(Error::NoTgtSession)
    }

    /// Return a service ticket from cache or acquire one from a KDC.
    pub async fn get_service_ticket(&mut self, service: Principal) -> Result<TgsRepSession, Error> {
        let service = self.resolve_service_principal(service);
        let key = service_cache_key(&service);
        if let Some(ticket) = self.service_tickets.get(&key).cloned() {
            let now = SystemTime::now();
            if session_valid_at(&ticket, now) {
                let mut ticket = ticket;
                ticket.service = service;
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
                let mut renewed = renewed;
                renewed.service = service;
                self.cache_service_ticket(renewed.clone());
                return Ok(renewed);
            }
        }

        let tgt = match self.cached_tgt_session_for_realm(&service.realm) {
            Some(tgt) => tgt,
            None if service.realm != self.client.realm => match self
                .renew_cached_tgt_session_for_realm(&service.realm)
                .await?
            {
                Some(tgt) => tgt,
                None => self.ensure_tgt().await?,
            },
            None => self.ensure_tgt().await?,
        };
        let result = self
            .transport
            .get_service_ticket_with_referral_trace(
                &self.config,
                self.protocol,
                &tgt,
                service,
                self.tgs_req_options()?,
            )
            .await?;
        for referral_tgt in result.referral_tgts {
            self.cache_tgt_session(referral_tgt)?;
        }
        let ticket = result.ticket;
        self.cache_service_ticket(ticket.clone());
        Ok(ticket)
    }

    /// Acquire an S4U2Self ticket for an impersonated user using the current service TGT.
    pub async fn s4u2self(&mut self, user: Principal) -> Result<TgsRepSession, Error> {
        let options = self.tgs_req_options()?;
        self.s4u2self_with_options(user, options).await
    }

    /// Acquire an S4U2Self ticket using explicit TGS request options.
    pub async fn s4u2self_with_options(
        &mut self,
        user: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let service_tgt = self.ensure_tgt().await?;
        self.transport
            .s4u2self_with_config(&self.config, self.protocol, &service_tgt, user, options)
            .await
    }

    /// Acquire an S4U2Proxy ticket for a target service using a user evidence ticket.
    pub async fn s4u2proxy(
        &mut self,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
    ) -> Result<TgsRepSession, Error> {
        let options = self.tgs_req_options()?;
        self.s4u2proxy_with_options(evidence_ticket, target_service, options)
            .await
    }

    /// Acquire an S4U2Proxy ticket using explicit TGS request options.
    pub async fn s4u2proxy_with_options(
        &mut self,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let service_tgt = self.ensure_tgt().await?;
        self.transport
            .s4u2proxy_with_config(
                &self.config,
                self.protocol,
                &service_tgt,
                evidence_ticket,
                target_service,
                options,
            )
            .await
    }

    /// Build a SPNEGO HTTP `Authorization` header for a service.
    #[cfg(feature = "spnego")]
    pub async fn spnego_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.spnego_context(service).await?.header)
    }

    /// Build a SPNEGO HTTP `Authorization` header with explicit initiator options.
    #[cfg(feature = "spnego")]
    pub async fn spnego_header_with_options(
        &mut self,
        service: Principal,
        options: crate::spnego::InitiatorContextOptions,
    ) -> Result<String, Error> {
        Ok(self
            .spnego_context_with_options(service, options)
            .await?
            .header)
    }

    /// Build a SPNEGO initiator context for a service.
    ///
    /// The returned context includes the HTTP `Authorization` header and the
    /// key material needed to verify an AP-REP response token.
    #[cfg(feature = "spnego")]
    pub async fn spnego_context(
        &mut self,
        service: Principal,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        self.spnego_context_with_options(service, crate::spnego::InitiatorContextOptions::new())
            .await
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    #[cfg(feature = "spnego")]
    pub async fn spnego_context_with_options(
        &mut self,
        service: Principal,
        options: crate::spnego::InitiatorContextOptions,
    ) -> Result<crate::spnego::InitiatorContext, Error> {
        let ticket = self.get_service_ticket(service).await?;
        Ok(crate::spnego::init_sec_context(&ticket, options)?)
    }

    async fn ensure_tgt(&mut self) -> Result<AsRepSession, Error> {
        if let Some(tgt) = self.tgt.clone() {
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) && !session_refresh_due_at(&tgt, now) {
                return Ok(tgt);
            }
            if session_renewable_at(&tgt, now) {
                return Ok(self.renew_tgt().await?.clone());
            }
            if session_valid_at(&tgt, now) && self.credentials.is_none() {
                return Ok(tgt);
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
        .with_assume_preauthentication(self.assume_preauthentication)
        .with_fast_negotiation(self.fast_negotiation))
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
        let mut credentials = Vec::with_capacity(
            self.tgt_sessions.len().max(usize::from(self.tgt.is_some()))
                + self.service_tickets.len(),
        );
        if self.tgt_sessions.is_empty() {
            if let Some(tgt) = &self.tgt {
                credentials.push(tgt.to_ccache_credential()?);
            }
        } else {
            for tgt in self.tgt_sessions.values() {
                credentials.push(tgt.to_ccache_credential()?);
            }
        }
        for ticket in self.service_tickets.values() {
            credentials.push(ticket.to_ccache_credential()?);
        }
        Ok(credentials)
    }

    fn cached_tgt_session_for_realm(&self, realm: &str) -> Option<AsRepSession> {
        let tgt = self.tgt_sessions.get(realm)?;
        session_valid_at(tgt, SystemTime::now()).then(|| tgt.clone())
    }

    async fn renew_cached_tgt_session_for_realm(
        &mut self,
        realm: &str,
    ) -> Result<Option<AsRepSession>, Error> {
        let Some(tgt) = self.tgt_sessions.get(realm).cloned() else {
            return Ok(None);
        };
        if !session_renewable_at(&tgt, SystemTime::now()) {
            return Ok(None);
        }

        let Ok(renewed) = self
            .transport
            .renew_tgt_with_config(&self.config, self.protocol, &tgt, self.tgs_req_options()?)
            .await
        else {
            return Ok(None);
        };
        let renewed_realm = tgt_realm(&renewed).ok_or_else(|| Error::InvalidTgtSession {
            service: renewed.service.name(),
        })?;
        if renewed_realm == self.client.realm {
            self.tgt = Some(renewed.clone());
        }
        self.tgt_sessions.insert(renewed_realm, renewed.clone());
        Ok(Some(renewed))
    }

    async fn diagnostic_kdc_endpoints(
        &self,
        protocol: KdcProtocol,
        errors: &mut Vec<String>,
    ) -> Vec<String> {
        match self
            .transport
            .discover_kdcs(&self.config, &self.client.realm, protocol)
            .await
        {
            Ok(endpoints) => endpoints.iter().map(KdcEndpoint::authority).collect(),
            Err(error) => {
                errors.push(format!(
                    "error when resolving KDCs for {} communication: {error}",
                    protocol_label(protocol)
                ));
                Vec::new()
            }
        }
    }
}

/// Small client API for HTTP Negotiate/SPNEGO initiator headers.
///
/// This wrapper keeps the stable HTTP-Negotiate surface narrow while reusing
/// [`TokioClient`] for ticket acquisition, cache reuse, and SPNEGO token
/// construction. Advanced Kerberos flows remain available on `TokioClient`.
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateClient {
    inner: TokioClient,
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
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
#[cfg(all(feature = "tokio", feature = "spnego"))]
pub struct BlockingNegotiateClient {
    runtime: tokio::runtime::Runtime,
    client: NegotiateClient,
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
impl fmt::Debug for BlockingNegotiateClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingNegotiateClient")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
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

#[cfg(all(feature = "tokio", feature = "spnego"))]
fn blocking_runtime() -> Result<tokio::runtime::Runtime, Error> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct SessionJsonEntry {
    realm: String,
    auth_time: String,
    end_time: String,
    renew_till: String,
    session_key_expiration: String,
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct ServiceTicketJsonEntry {
    #[serde(rename = "SPN")]
    spn: String,
    auth_time: String,
    start_time: String,
    end_time: String,
    renew_till: String,
}

#[cfg(all(feature = "tokio", feature = "serde"))]
fn session_json_entry(session: &AsRepSession) -> SessionJsonEntry {
    SessionJsonEntry {
        realm: session.service.realm.clone(),
        auth_time: json_time(session.auth_time),
        end_time: json_time(session.end_time),
        renew_till: json_time(session.renew_till.unwrap_or(session.end_time)),
        session_key_expiration: json_time(session.key_expiration.unwrap_or(session.end_time)),
    }
}

#[cfg(all(feature = "tokio", feature = "serde"))]
fn service_ticket_json_entry(ticket: &TgsRepSession) -> ServiceTicketJsonEntry {
    ServiceTicketJsonEntry {
        spn: ticket.service.name(),
        auth_time: json_time(ticket.auth_time),
        start_time: json_time(ticket.start_time),
        end_time: json_time(ticket.end_time),
        renew_till: json_time(ticket.renew_till.unwrap_or(ticket.end_time)),
    }
}

#[cfg(all(feature = "tokio", feature = "serde"))]
fn json_time(time: SystemTime) -> String {
    let timestamp: chrono::DateTime<chrono::Utc> = time.into();
    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(feature = "tokio")]
fn credential_source(credentials: Option<&TokioClientCredentials>) -> &'static str {
    match credentials {
        Some(TokioClientCredentials::Password(_)) => "password",
        Some(TokioClientCredentials::Keytab(_)) => "keytab",
        None => "none",
    }
}

#[cfg(feature = "tokio")]
fn keytab_realm_enctypes(keytab: &Keytab, realm: &str) -> Vec<i32> {
    let mut enctypes = keytab
        .entries()
        .iter()
        .filter(|entry| entry.principal.realm == realm)
        .map(|entry| entry.key.etype)
        .collect::<Vec<_>>();
    enctypes.sort_unstable();
    enctypes.dedup();
    enctypes
}

#[cfg(feature = "tokio")]
fn record_keytab_enctype_diagnostics(
    errors: &mut Vec<String>,
    keytab_enctypes: &[i32],
    configured: &[i32],
    field: &str,
) {
    for etype in configured {
        if !keytab_enctypes.contains(etype) {
            errors.push(format!(
                "{field} specifies {etype} but this enctype is not available in the client's keytab"
            ));
        }
    }
}

#[cfg(feature = "tokio")]
fn protocol_label(protocol: KdcProtocol) -> &'static str {
    match protocol {
        KdcProtocol::Udp => "UDP",
        KdcProtocol::Tcp => "TCP",
        KdcProtocol::Auto => "Auto",
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
    let req_body = rasn_kerberos::KdcReqBody {
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
    };
    let message = crate::kdc_req::build_as_req(req_body, padata);
    let der = crate::kdc_req::encode_as_req(&message).map_err(kdc_req_error)?;

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

/// Build the MS-SFU byte array signed by PA-FOR-USER.
pub fn s4u_byte_array(user: &Principal, auth_package: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + user.components.iter().map(String::len).sum::<usize>()
            + user.realm.len()
            + auth_package.len(),
    );
    out.extend_from_slice(&user.name_type.to_le_bytes());
    for component in &user.components {
        out.extend_from_slice(component.as_bytes());
    }
    out.extend_from_slice(user.realm.as_bytes());
    out.extend_from_slice(auth_package.as_bytes());
    out
}

/// Build PA-FOR-USER padata using the default `Kerberos` auth package.
pub fn pa_for_user_padata(
    user: &Principal,
    tgt_session_key: &EncryptionKey,
) -> Result<rasn_kerberos::PaData, Error> {
    pa_for_user_padata_with_auth_package(user, tgt_session_key, "Kerberos")
}

/// Build PA-FOR-USER padata for S4U2Self.
pub fn pa_for_user_padata_with_auth_package(
    user: &Principal,
    tgt_session_key: &EncryptionKey,
    auth_package: &str,
) -> Result<rasn_kerberos::PaData, Error> {
    let s4u_bytes = s4u_byte_array(user, auth_package);
    let checksum = kerb_checksum_hmac_md5(
        &tgt_session_key.value,
        &s4u_bytes,
        PA_FOR_USER_CHECKSUM_USAGE,
    );
    let value = crate::messages::PaForUser {
        user_name: principal_to_rasn(user)?,
        user_realm: kerberos_string(&user.realm)?,
        cksum: rasn_kerberos::Checksum {
            r#type: Rc4HmacEtype.checksum_type_id(),
            checksum: checksum.into(),
        },
        auth_package: kerberos_string(auth_package)?,
    };

    Ok(rasn_kerberos::PaData {
        r#type: PA_FOR_USER,
        value: value.encode_der()?.into(),
    })
}

/// Build PA-PAC-OPTIONS padata from a raw PAC option bit mask.
pub fn pa_pac_options_padata(option_bits: u32) -> Result<rasn_kerberos::PaData, Error> {
    let value = crate::messages::PaPacOptions::from_bits(option_bits);
    Ok(rasn_kerberos::PaData {
        r#type: PA_PAC_OPTIONS,
        value: value.encode_der()?.into(),
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

/// Build an AS-REQ for an explicit service principal with PA-ENC-TIMESTAMP preauthentication.
pub fn build_preauthenticated_as_req(
    client: Principal,
    service: Principal,
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
    build_as_req(client, service, options)
}

/// Build a TGT AS-REQ with PA-ENC-TIMESTAMP preauthentication.
pub fn build_preauthenticated_tgt_as_req(
    client: Principal,
    options: AsReqOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<BuiltAsReq, Error> {
    let service = Principal::tgt_service(client.realm.clone());
    build_preauthenticated_as_req(client, service, options, key, kvno)
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

/// Build an S4U2Self TGS-REQ using the supplied service TGT.
///
/// The requested service is the TGT client principal, and the impersonated user
/// is carried in PA-FOR-USER.
pub fn build_s4u2self_req(
    service_tgt: &AsRepSession,
    user: Principal,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(service_tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_s4u2self_req_with_confounder(service_tgt, user, options, timestamp, cusec, &confounder)
}

/// Build a deterministic S4U2Self TGS-REQ with an explicit authenticator timestamp and confounder.
pub fn build_s4u2self_req_with_confounder(
    service_tgt: &AsRepSession,
    user: Principal,
    mut options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    options.padata.retain(|padata| padata.r#type != PA_FOR_USER);
    options
        .padata
        .push(pa_for_user_padata(&user, &service_tgt.session_key)?);
    let service = service_tgt.client.clone();
    let mut request = build_tgs_req_for_realm_with_confounder(
        service_tgt,
        service.realm.clone(),
        service,
        options,
        timestamp,
        cusec,
        confounder,
    )?;
    request.client = user;
    Ok(request)
}

/// Build an S4U2Proxy TGS-REQ using a service TGT and user evidence ticket.
pub fn build_s4u2proxy_req(
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    options: TgsReqOptions,
) -> Result<BuiltTgsReq, Error> {
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(service_tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_s4u2proxy_req_with_confounder(
        service_tgt,
        evidence_ticket,
        target_service,
        options,
        timestamp,
        cusec,
        &confounder,
    )
}

/// Build a deterministic S4U2Proxy TGS-REQ with an explicit authenticator timestamp and confounder.
pub fn build_s4u2proxy_req_with_confounder(
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    mut options: TgsReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    if !principal_matches(&evidence_ticket.service, &service_tgt.client) {
        return Err(Error::ServicePrincipalMismatch {
            expected: service_tgt.client.name(),
            actual: evidence_ticket.service.name(),
        });
    }
    options.kdc_option_bits |= KDC_OPTION_CNAME_IN_ADDL_TKT;
    options
        .additional_tickets
        .push(crate::ticket::decode_ticket(&evidence_ticket.ticket).map_err(ticket_error)?);
    let mut request = build_tgs_req_for_realm_with_confounder(
        service_tgt,
        target_service.realm.clone(),
        target_service,
        options,
        timestamp,
        cusec,
        confounder,
    )?;
    request.client = evidence_ticket.client.clone();
    Ok(request)
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
    let ticket = crate::ticket::decode_ticket(&tgt.ticket).map_err(ticket_error)?;
    let till = options
        .now
        .checked_add(options.ticket_lifetime)
        .ok_or(Error::TimeOverflow)?;
    let renew_till = options
        .renew_lifetime
        .map(|duration| options.now.checked_add(duration).ok_or(Error::TimeOverflow))
        .transpose()?;
    let additional_tickets =
        (!options.additional_tickets.is_empty()).then_some(options.additional_tickets);
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
        additional_tickets,
    };
    let req_body_der = crate::kdc_req::encode_kdc_req_body(&req_body).map_err(kdc_req_error)?;
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
    let authenticator_kvno = ticket.enc_part.kvno;
    let ap_req = crate::ap_req::build_ap_req_with_confounder(
        ticket,
        crate::ap_req::ap_options_from_bits(0),
        &authenticator,
        &tgt.session_key,
        TGS_REQ_AUTHENTICATOR_USAGE,
        authenticator_kvno,
        confounder,
    )
    .map_err(ap_req_error)?;
    let pa_tgs_req = rasn_kerberos::PaData {
        r#type: PA_TGS_REQ,
        value: crate::ap_req::encode_ap_req(&ap_req)
            .map_err(ap_req_error)?
            .into(),
    };
    let mut padata = Vec::with_capacity(options.padata.len() + 1);
    padata.push(pa_tgs_req);
    padata.extend(options.padata);
    let message = crate::kdc_req::build_tgs_req(req_body, Some(padata));
    let der = crate::kdc_req::encode_tgs_req(&message).map_err(kdc_req_error)?;

    Ok(BuiltTgsReq {
        message,
        der,
        client: tgt.client.clone(),
        kdc_realm,
        service,
        nonce: options.nonce,
    })
}

/// Build a client AP-REQ with an explicit authenticator timestamp and confounder.
pub fn build_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    options: ApReqOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    let ticket = crate::ticket::decode_ticket(&service_ticket.ticket).map_err(ticket_error)?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: rasn::types::Integer::from(KRB5_PVNO),
        crealm: kerberos_string(&service_ticket.client.realm)?,
        cname: principal_to_rasn(&service_ticket.client)?,
        cksum: options.checksum,
        cusec: rasn::types::Integer::from(cusec),
        ctime: kerberos_time_from_system_time(timestamp)?,
        subkey: options.subkey.as_ref().map(encryption_key_to_rasn),
        seq_number: options.sequence_number,
        authorization_data: None,
    };
    let authenticator_usage = crate::ap_req::authenticator_usage_for_ticket(&ticket);
    let authenticator_kvno = ticket.enc_part.kvno;
    let message = crate::ap_req::build_ap_req_with_confounder(
        ticket,
        crate::ap_req::ap_options_from_bits(options.ap_option_bits),
        &authenticator,
        &service_ticket.session_key,
        authenticator_usage,
        authenticator_kvno,
        confounder,
    )
    .map_err(ap_req_error)?;
    let der = crate::ap_req::encode_ap_req(&message).map_err(ap_req_error)?;
    let authenticator_time = timestamp
        .checked_add(Duration::from_micros(cusec.into()))
        .ok_or(Error::TimeOverflow)?;

    Ok(BuiltApReq {
        message,
        der,
        client: service_ticket.client.clone(),
        service: service_ticket.service.clone(),
        session_key: service_ticket.session_key.clone(),
        authenticator_ctime: timestamp,
        authenticator_cusec: cusec,
        authenticator_time,
        sequence_number: options.sequence_number,
        subkey: options.subkey,
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

/// Perform S4U2Self through a runtime-neutral transport.
pub fn s4u2self<T>(
    transport: &mut T,
    service_tgt: &AsRepSession,
    user: Principal,
    options: TgsReqOptions,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_s4u2self_req(service_tgt, user, options)?;
    exchange_tgs_req(transport, &request, &service_tgt.session_key)
}

/// Perform S4U2Proxy through a runtime-neutral transport.
pub fn s4u2proxy<T>(
    transport: &mut T,
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    options: TgsReqOptions,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
    exchange_tgs_req(transport, &request, &service_tgt.session_key)
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
    let service = Principal::tgt_service(client.realm.clone());
    login_as_service_with_password(transport, client, service, password, options)
}

/// Perform an AS login for an explicit service using password credentials and KDC preauth hints.
pub fn login_as_service_with_password<T>(
    transport: &mut T,
    client: Principal,
    service: Principal,
    password: &[u8],
    options: AsReqOptions,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request =
        password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
    let initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
    {
        return Ok(session);
    }
    let (request, reply_key) =
        password_preauth_request(client, service, password, options, &initial_response)?;
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
    let service = Principal::tgt_service(client.realm.clone());
    login_as_service_with_keytab(transport, client, service, keytab, options)
}

/// Perform an AS login for an explicit service using keytab credentials and KDC preauth hints.
pub fn login_as_service_with_keytab<T>(
    transport: &mut T,
    client: Principal,
    service: Principal,
    keytab: &Keytab,
    options: AsReqOptions,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request =
        keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
    let initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
    {
        return Ok(session);
    }
    let (request, reply_key) =
        keytab_preauth_request(client, service, keytab, options, &initial_response)?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(&request, &response, &reply_key)
}

/// Decrypt and validate an AS-REP against the original AS-REQ.
pub fn process_as_rep(
    request: &BuiltAsReq,
    bytes: &[u8],
    reply_key: &EncryptionKey,
) -> Result<AsRepSession, Error> {
    if let Ok(error) = process_kdc_error(bytes) {
        return Err(Error::Kdc(Box::new(error)));
    }

    let as_rep = crate::kdc_rep::decode_as_rep(bytes).map_err(kdc_rep_error)?;
    let kdc_rep = &as_rep.0;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::ClientPrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    let enc_part =
        crate::kdc_rep::decrypt_as_rep_enc_part(&as_rep, reply_key).map_err(kdc_rep_error)?;
    validate_as_rep_encrypted_padata(request, &enc_part, reply_key)?;

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

    let ticket = crate::ticket::encode_ticket(&kdc_rep.ticket).map_err(ticket_error)?;
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
        key_expiration: enc_part
            .key_expiration
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

fn validate_as_rep_encrypted_padata(
    request: &BuiltAsReq,
    enc_part: &rasn_kerberos::EncKdcRepPart,
    reply_key: &EncryptionKey,
) -> Result<(), Error> {
    if !as_req_contains_padata(request, PA_REQ_ENC_PA_REP)
        || !ticket_flags_contain_bits(&enc_part.flags, TICKET_FLAG_ENC_PA_REP)
    {
        return Ok(());
    }

    let encrypted_pa_data = enc_part
        .encrypted_pa_data
        .as_ref()
        .ok_or(Error::InvalidFastNegotiationResponse)?;
    if encrypted_pa_data.len() < 2 || !padata_contains(encrypted_pa_data, PA_FX_FAST) {
        return Err(Error::InvalidFastNegotiationResponse);
    }
    let pa_req_enc_pa_rep = encrypted_pa_data
        .iter()
        .find(|padata| padata.r#type == PA_REQ_ENC_PA_REP)
        .ok_or(Error::InvalidFastNegotiationResponse)?;
    let checksum = crate::messages::PaReqEncPaRep::decode_der(pa_req_enc_pa_rep.value.as_ref())?;
    let etype = KerberosEtype::from_checksum_type_id(checksum.checksum_type)
        .ok_or(Error::UnsupportedChecksumType(checksum.checksum_type))?;
    if !etype.verify_checksum(
        &reply_key.value,
        &request.der,
        checksum.checksum.as_ref(),
        AS_REQ_CHECKSUM_USAGE,
    ) {
        return Err(Error::FastNegotiationChecksumMismatch);
    }
    Ok(())
}

fn as_req_contains_padata(request: &BuiltAsReq, padata_type: i32) -> bool {
    request
        .message
        .0
        .padata
        .as_ref()
        .is_some_and(|padata| padata_contains(padata, padata_type))
}

fn padata_contains(padata: &[rasn_kerberos::PaData], padata_type: i32) -> bool {
    padata.iter().any(|padata| padata.r#type == padata_type)
}

fn ticket_flags_contain_bits(flags: &rasn_kerberos::TicketFlags, bits: u32) -> bool {
    u32::from_be_bytes(ticket_flags_to_bytes(flags)) & bits == bits
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
    if let Ok(error) = process_kdc_error(bytes) {
        return Err(Error::Kdc(Box::new(error)));
    }

    let tgs_rep = crate::kdc_rep::decode_tgs_rep(bytes).map_err(kdc_rep_error)?;
    let kdc_rep = &tgs_rep.0;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::ClientPrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    let enc_part = crate::kdc_rep::decrypt_tgs_rep_enc_part(&tgs_rep, tgs_session_key)
        .map_err(kdc_rep_error)?;

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

    let ticket = crate::ticket::encode_ticket(&kdc_rep.ticket).map_err(ticket_error)?;
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
        key_expiration: enc_part
            .key_expiration
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

/// Decode a KRB-ERROR and any METHOD-DATA preauthentication hints.
pub fn process_kdc_error(bytes: &[u8]) -> Result<KdcError, Error> {
    let krb_error = crate::krb_error::decode_krb_error(bytes).map_err(krb_error_error)?;
    let info = crate::krb_error::krb_error_info(&krb_error).map_err(krb_error_error)?;
    let e_data = info.e_data;
    let method_data = crate::krb_error::preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED)
        .map_err(krb_error_error)?;
    let preauth_key_info = preauth_key_info_from_method_data(&method_data)?;

    Ok(KdcError {
        ctime: info.ctime,
        cusec: info.cusec,
        stime: info.stime,
        susec: info.susec,
        error_code: info.error_code,
        text: info.e_text,
        client: info.client.map(principal_from_message_info),
        service: principal_from_message_info(info.service),
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

    /// A human-readable Kerberos principal name was invalid.
    #[error("invalid Kerberos principal name {value:?}: {reason}")]
    InvalidPrincipalName {
        /// Input principal string.
        value: String,
        /// Validation failure.
        reason: &'static str,
    },

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

    /// Message integer field could not be represented as `u32`.
    #[error("invalid {field}: expected unsigned 32-bit integer, got {actual}")]
    InvalidUnsignedInteger {
        /// Field name.
        field: &'static str,
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

    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    ApRepKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    ApReqKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Service key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// A successful kpasswd reply did not contain AP-REP.
    #[error("kpasswd reply does not contain AP-REP")]
    MissingKpasswdApRep,

    /// A kpasswd AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("kpasswd AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    KpasswdApRepTimestampMismatch {
        /// Timestamp supplied by the AP-REQ authenticator.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
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

    /// The AS-REP did not include the encrypted padata required by FAST negotiation.
    #[error("KDC did not respond appropriately to FAST negotiation")]
    InvalidFastNegotiationResponse,

    /// The AS-REP FAST negotiation checksum used an unsupported checksum type.
    #[error("unsupported Kerberos checksum type: {0}")]
    UnsupportedChecksumType(i32),

    /// The AS-REP FAST negotiation checksum was invalid.
    #[error("KDC FAST negotiation response checksum invalid")]
    FastNegotiationChecksumMismatch,

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

    /// A configured credential-cache load needs `default_ccache_name`.
    #[cfg(feature = "tokio")]
    #[error("config.libdefaults.default_ccache_name is not configured")]
    NoDefaultCCacheName,

    /// The default client keytab name could not be read from `KRB5_CLIENT_KTNAME`.
    #[cfg(feature = "tokio")]
    #[error("default client keytab name could not be read from KRB5_CLIENT_KTNAME: {0}")]
    DefaultClientKeytabName(std::env::VarError),

    /// A high-level client operation needs a non-empty client principal name.
    #[cfg(feature = "tokio")]
    #[error("client principal name is not configured")]
    MissingClientName,

    /// A high-level client operation needs a non-empty client realm.
    #[cfg(feature = "tokio")]
    #[error("client principal realm is not configured")]
    MissingClientRealm,

    /// KDC DNS lookup is disabled and no configured KDC exists for the realm.
    #[cfg(feature = "tokio")]
    #[error("no configured KDC exists for realm {realm}")]
    NoConfiguredKdc {
        /// Realm missing a configured KDC.
        realm: String,
    },

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

    /// kadmin protocol processing failed.
    #[error("kadmin error: {0}")]
    Kadmin(#[from] crate::kadmin::Error),

    /// Kerberos message helper failed.
    #[error("message error: {0}")]
    Message(#[from] crate::messages::Error),

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

fn ap_req_error(error: crate::ap_req::Error) -> Error {
    match error {
        crate::ap_req::Error::Decode { target, message } => Error::Decode { target, message },
        crate::ap_req::Error::Encode { target, message } => Error::Encode { target, message },
        crate::ap_req::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::ap_req::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::ap_req::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApReqKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::ap_req::Error::Random(source) => Error::Random(source),
        crate::ap_req::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn kdc_req_error(error: crate::kdc_req::Error) -> Error {
    match error {
        crate::kdc_req::Error::Decode { target, message } => Error::Decode { target, message },
        crate::kdc_req::Error::Encode { target, message } => Error::Encode { target, message },
        crate::kdc_req::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::kdc_req::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::kdc_req::Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::kdc_req::Error::Random(source) => Error::Random(source),
        crate::kdc_req::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn krb_error_error(error: crate::krb_error::Error) -> Error {
    match error {
        crate::krb_error::Error::Decode { target, message } => Error::Decode { target, message },
        crate::krb_error::Error::Encode { target, message } => Error::Encode { target, message },
        crate::krb_error::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::krb_error::Error::IntegerOutOfRange { field, value } => {
            Error::InvalidUnsignedInteger {
                field,
                actual: value,
            }
        }
        crate::krb_error::Error::TimeOverflow => Error::TimeOverflow,
        other => Error::Decode {
            target: "KRB-ERROR",
            message: other.to_string(),
        },
    }
}

fn ticket_error(error: crate::ticket::Error) -> Error {
    match error {
        crate::ticket::Error::Decode { target, message } => Error::Decode { target, message },
        crate::ticket::Error::Encode { target, message } => Error::Encode { target, message },
        crate::ticket::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::ticket::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::ticket::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::ticket::Error::Random(source) => Error::Random(source),
        crate::ticket::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn kdc_rep_error(error: crate::kdc_rep::Error) -> Error {
    match error {
        crate::kdc_rep::Error::Decode { target, message } => Error::Decode { target, message },
        crate::kdc_rep::Error::Encode { target, message } => Error::Encode { target, message },
        crate::kdc_rep::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::kdc_rep::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::kdc_rep::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::kdc_rep::Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::kdc_rep::Error::Random(source) => Error::Random(source),
        crate::kdc_rep::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn ap_rep_error(error: crate::ap_rep::Error) -> Error {
    match error {
        crate::ap_rep::Error::Decode { target, message } => Error::Decode { target, message },
        crate::ap_rep::Error::Encode { target, message } => Error::Encode { target, message },
        crate::ap_rep::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::ap_rep::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::ap_rep::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApRepKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::ap_rep::Error::Random(source) => Error::Random(source),
        crate::ap_rep::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn password_preauth_request(
    client: Principal,
    service: Principal,
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
    let options = initial_preauth_probe_options(options);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, None)?;
    Ok((request, reply_key))
}

fn password_initial_as_req(
    client: Principal,
    service: Principal,
    password: &[u8],
    options: AsReqOptions,
) -> Result<BuiltAsReq, Error> {
    let options = initial_preauth_probe_options(options);
    if options.assume_preauthentication {
        let key_info = assumed_preauth_key_info(&options.etypes)?;
        let reply_key = derive_password_reply_key(&client, password, &key_info)?;
        build_preauthenticated_as_req(client, service, options, &reply_key, None)
    } else {
        build_as_req(client, service, options)
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
    service: Principal,
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
    let options = initial_preauth_probe_options(options);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, Some(kvno))?;
    Ok((request, reply_key))
}

fn keytab_initial_as_req(
    client: Principal,
    service: Principal,
    keytab: &Keytab,
    options: AsReqOptions,
) -> Result<BuiltAsReq, Error> {
    let options = initial_preauth_probe_options(options);
    if options.assume_preauthentication {
        let (reply_key, kvno) = select_assumed_keytab_reply_key(keytab, &client, &options)?;
        build_preauthenticated_as_req(client, service, options, &reply_key, Some(kvno))
    } else {
        build_as_req(client, service, options)
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
    if options.fast_negotiation
        && !options
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
    crate::kdc_rep::decode_as_rep(response)
        .ok()
        .map(|as_rep| (as_rep.0.enc_part.etype, as_rep.0.enc_part.kvno))
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

fn principal_from_message_info(value: crate::messages::PrincipalNameInfo) -> Principal {
    Principal {
        realm: value.realm,
        name_type: value.name_type,
        components: value.components,
    }
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

fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
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
fn configured_default_ccache_name(config: &Config) -> Result<String, Error> {
    let cache_name = config.libdefaults.default_ccache_name.clone();
    if cache_name.is_empty() {
        return Err(Error::NoDefaultCCacheName);
    }
    Ok(cache_name)
}

#[cfg(feature = "tokio")]
fn default_ccache_name(config: &Config) -> Result<String, Error> {
    match std::env::var(KRB5CCNAME_ENV) {
        Ok(cache_name) => Ok(cache_name),
        Err(std::env::VarError::NotPresent) => configured_default_ccache_name(config),
        Err(error) => Err(ccache::Error::DefaultCacheName(error).into()),
    }
}

#[cfg(feature = "tokio")]
fn default_client_keytab_name(config: &Config) -> Result<String, Error> {
    match std::env::var(KRB5_CLIENT_KTNAME_ENV) {
        Ok(keytab_name) => Ok(keytab_name),
        Err(std::env::VarError::NotPresent) => {
            Ok(config.libdefaults.default_client_keytab_name.clone())
        }
        Err(error) => Err(Error::DefaultClientKeytabName(error)),
    }
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
        key_expiration: None,
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
fn session_usable_at(session: &AsRepSession, now: SystemTime) -> bool {
    session_valid_at(session, now) || session_renewable_at(session, now)
}

#[cfg(feature = "tokio")]
fn session_refresh_due_at(session: &AsRepSession, now: SystemTime) -> bool {
    if now >= session.end_time {
        return true;
    }
    let Ok(lifetime) = session.end_time.duration_since(session.auth_time) else {
        return true;
    };
    if lifetime.is_zero() {
        return true;
    }
    let remaining = session
        .end_time
        .duration_since(now)
        .unwrap_or(Duration::ZERO);
    remaining <= lifetime / SESSION_REFRESH_DIVISOR
}

#[cfg(feature = "tokio")]
fn session_refresh_delay_at(session: &AsRepSession, now: SystemTime) -> Duration {
    if session_refresh_due_at(session, now) {
        return Duration::ZERO;
    }
    let Ok(lifetime) = session.end_time.duration_since(session.auth_time) else {
        return Duration::ZERO;
    };
    let Some(refresh_at) = session
        .end_time
        .checked_sub(lifetime / SESSION_REFRESH_DIVISOR)
    else {
        return Duration::ZERO;
    };
    refresh_at.duration_since(now).unwrap_or(Duration::ZERO)
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

fn integer_to_u32(field: &'static str, value: &rasn::types::Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .map_err(|_| Error::InvalidUnsignedInteger {
            field,
            actual: value.to_string(),
        })
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
