//! AS exchange client-side primitives.
//!
//! This module covers the first client slice needed for gokrb5-compatible
//! login flows: deterministic AS-REQ construction, PA-ENC-TIMESTAMP
//! preauthentication, a KDC transport boundary, and AS-REP encrypted-part
//! validation. Live KDC discovery and Tokio transport adapters sit above this
//! runtime-neutral core.

#[cfg(feature = "tokio")]
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ccache;
use crate::config::LibDefaults;
use crate::crypto::AesSha1Etype;
use crate::keytab::EncryptionKey;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

const KRB5_PVNO: i32 = 5;
const KRB_AS_REQ_MSG_TYPE: i32 = 10;
const KRB_AS_REP_MSG_TYPE: i32 = 11;
const KRB_NT_PRINCIPAL: i32 = 1;
const KRB_NT_SRV_INST: i32 = 2;
const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_TKT_ENCTYPES: &[i32] = &[18, 17];
#[cfg(feature = "tokio")]
const DEFAULT_KDC_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "tokio")]
const DEFAULT_TCP_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
#[cfg(feature = "tokio")]
const MAX_UDP_DATAGRAM: usize = 65_507;

/// PA-ENC-TIMESTAMP preauthentication type.
pub const PA_ENC_TIMESTAMP: i32 = 2;

/// Key usage for AS-REQ encrypted timestamp preauthentication.
pub const AS_REQ_PA_ENC_TIMESTAMP_USAGE: u32 = 1;

/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = 3;

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

/// Runtime-neutral boundary for KDC request/response transport.
pub trait KdcTransport {
    /// Send an encoded KDC request and return the encoded KDC response.
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error>;
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
    let message = rasn_kerberos::AsReq(rasn_kerberos::KdcReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AS_REQ_MSG_TYPE),
        padata,
        req_body: rasn_kerberos::KdcReqBody {
            kdc_options: kdc_options_from_bits(options.kdc_option_bits),
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
    let etype = AesSha1Etype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
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

/// AS exchange client error.
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
    #[error("AS-REQ must request at least one encryption type")]
    EmptyEtypes,

    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),

    /// A reply key did not match the AS-REP encrypted data etype.
    #[error(
        "reply key etype {key_etype} does not match AS-REP encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AS-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// The AS-REP client principal did not match the AS-REQ.
    #[error("AS-REP client {actual} does not match requested client {expected}")]
    ClientPrincipalMismatch {
        /// Expected request client.
        expected: String,
        /// Actual reply client.
        actual: String,
    },

    /// The AS-REP service principal did not match the AS-REQ.
    #[error("AS-REP service {actual} does not match requested service {expected}")]
    ServicePrincipalMismatch {
        /// Expected request service.
        expected: String,
        /// Actual reply service.
        actual: String,
    },

    /// The AS-REP nonce did not match the AS-REQ nonce.
    #[error("AS-REP nonce {actual} does not match AS-REQ nonce {expected}")]
    NonceMismatch {
        /// Expected request nonce.
        expected: u32,
        /// Actual reply nonce.
        actual: u32,
    },

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,

    /// Tokio transport I/O failed.
    #[cfg(feature = "tokio")]
    #[error("KDC transport I/O failed: {0}")]
    Io(#[from] std::io::Error),

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
    let etype = AesSha1Etype::from_etype_id(etype_id).ok_or(Error::UnsupportedEtype(etype_id))?;
    Ok(etype.decrypt_message(key, ciphertext, usage)?)
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

#[cfg(feature = "tokio")]
fn non_empty_kdc_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
    if response.is_empty() {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(response)
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
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .ok_or(Error::TimeOverflow)?;
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
