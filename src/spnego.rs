//! SPNEGO and GSS-API Kerberos token helpers.
//!
//! This module covers the service-side wrapper layer around the Kerberos
//! messages handled by [`crate::service`]: GSS-API KRB5 mech tokens, SPNEGO
//! NegTokenInit/NegTokenResp negotiation tokens, and HTTP `Negotiate` header
//! encoding/decoding.

use base64::Engine as _;

use crate::service::{ApRepOptions, ServiceValidator, ValidatedApReq};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_APPLICATION_0: u8 = 0x60;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_1: u8 = 0xa1;
const TAG_CONTEXT_2: u8 = 0xa2;
const TAG_CONTEXT_3: u8 = 0xa3;

const TOK_ID_KRB_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_ID_KRB_AP_REP: [u8; 2] = [0x02, 0x00];
const TOK_ID_KRB_ERROR: [u8; 2] = [0x03, 0x00];

/// HTTP request header that carries SPNEGO authentication data.
pub const HTTP_AUTHORIZATION: &str = "Authorization";
/// HTTP response header that carries SPNEGO authentication data.
pub const HTTP_WWW_AUTHENTICATE: &str = "WWW-Authenticate";
/// HTTP authentication scheme used by SPNEGO.
pub const HTTP_NEGOTIATE: &str = "Negotiate";

/// GSS-API context flag: delegation.
pub const CONTEXT_FLAG_DELEG: u32 = 1;
/// GSS-API context flag: mutual authentication.
pub const CONTEXT_FLAG_MUTUAL: u32 = 2;
/// GSS-API context flag: replay detection.
pub const CONTEXT_FLAG_REPLAY: u32 = 4;
/// GSS-API context flag: sequencing.
pub const CONTEXT_FLAG_SEQUENCE: u32 = 8;
/// GSS-API context flag: confidentiality.
pub const CONTEXT_FLAG_CONF: u32 = 16;
/// GSS-API context flag: integrity.
pub const CONTEXT_FLAG_INTEG: u32 = 32;
/// GSS-API context flag: anonymity.
pub const CONTEXT_FLAG_ANON: u32 = 64;

/// GSS-API object identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectIdentifier(Vec<u32>);

impl ObjectIdentifier {
    /// Kerberos 5 mechanism OID: `1.2.840.113554.1.2.2`.
    pub fn krb5() -> Self {
        Self(vec![1, 2, 840, 113_554, 1, 2, 2])
    }

    /// Microsoft legacy Kerberos mechanism OID: `1.2.840.48018.1.2.2`.
    pub fn ms_legacy_krb5() -> Self {
        Self(vec![1, 2, 840, 48_018, 1, 2, 2])
    }

    /// SPNEGO mechanism OID: `1.3.6.1.5.5.2`.
    pub fn spnego() -> Self {
        Self(vec![1, 3, 6, 1, 5, 5, 2])
    }

    /// Construct an object identifier from arcs.
    pub fn from_arcs(arcs: Vec<u32>) -> Result<Self, Error> {
        validate_oid_arcs(&arcs)?;
        Ok(Self(arcs))
    }

    /// OID arcs.
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// Whether this OID is one of the Kerberos mechanism OIDs accepted by
    /// gokrb5's SPNEGO verifier.
    pub fn is_kerberos_mechanism(&self) -> bool {
        self == &Self::krb5() || self == &Self::ms_legacy_krb5()
    }
}

/// GSS-API KRB5 mech token type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Krb5TokenId {
    /// AP-REQ token, `01 00`.
    ApReq,
    /// AP-REP token, `02 00`.
    ApRep,
    /// KRB-ERROR token, `03 00`.
    KrbError,
}

impl Krb5TokenId {
    fn bytes(self) -> [u8; 2] {
        match self {
            Self::ApReq => TOK_ID_KRB_AP_REQ,
            Self::ApRep => TOK_ID_KRB_AP_REP,
            Self::KrbError => TOK_ID_KRB_ERROR,
        }
    }

    fn from_bytes(bytes: [u8; 2]) -> Result<Self, Error> {
        match bytes {
            TOK_ID_KRB_AP_REQ => Ok(Self::ApReq),
            TOK_ID_KRB_AP_REP => Ok(Self::ApRep),
            TOK_ID_KRB_ERROR => Ok(Self::KrbError),
            actual => Err(Error::UnknownKrb5TokenId(actual)),
        }
    }
}

/// GSS-API KRB5 mech token containing one Kerberos message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Krb5MechToken {
    /// Token mechanism OID. RFC 4121 KRB5 tokens use [`ObjectIdentifier::krb5`].
    pub oid: ObjectIdentifier,
    /// Two-byte KRB5 token ID.
    pub token_id: Krb5TokenId,
    /// DER-encoded Kerberos message carried by this token.
    pub message: Vec<u8>,
}

impl Krb5MechToken {
    /// Build a KRB5 AP-REQ mech token.
    pub fn ap_req(message: Vec<u8>) -> Self {
        Self::new(Krb5TokenId::ApReq, message)
    }

    /// Build a KRB5 AP-REP mech token.
    pub fn ap_rep(message: Vec<u8>) -> Self {
        Self::new(Krb5TokenId::ApRep, message)
    }

    /// Build a KRB5 mech token with the standard Kerberos 5 mechanism OID.
    pub fn new(token_id: Krb5TokenId, message: Vec<u8>) -> Self {
        Self {
            oid: ObjectIdentifier::krb5(),
            token_id,
            message,
        }
    }

    /// Decode a GSS-API KRB5 mech token.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut outer = DerReader::new(bytes);
        let token = outer.read_tlv()?;
        outer.finish()?;
        if token.tag != TAG_APPLICATION_0 {
            return Err(Error::UnexpectedTag {
                expected: TAG_APPLICATION_0,
                actual: token.tag,
            });
        }

        let mut content = DerReader::new(token.value);
        let oid = decode_oid_tlv(content.read_tlv()?)?;
        if oid != ObjectIdentifier::krb5() {
            return Err(Error::UnsupportedMechanism(oid));
        }

        let tok_id = content.read_bytes(2)?;
        let token_id = Krb5TokenId::from_bytes([tok_id[0], tok_id[1]])?;
        let message = content.remaining().to_vec();
        if message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }
        Ok(Self {
            oid,
            token_id,
            message,
        })
    }

    /// Encode this token to DER.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }

        let mut content = encode_oid(&self.oid)?;
        content.extend_from_slice(&self.token_id.bytes());
        content.extend_from_slice(&self.message);
        Ok(encode_tlv(TAG_APPLICATION_0, &content))
    }

    /// Return the AP-REQ bytes if this is an AP-REQ token.
    pub fn ap_req_bytes(&self) -> Option<&[u8]> {
        (self.token_id == Krb5TokenId::ApReq).then_some(self.message.as_slice())
    }

    /// Return the AP-REP bytes if this is an AP-REP token.
    pub fn ap_rep_bytes(&self) -> Option<&[u8]> {
        (self.token_id == Krb5TokenId::ApRep).then_some(self.message.as_slice())
    }
}

/// SPNEGO negotiation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegState {
    /// `accept-completed`.
    AcceptCompleted,
    /// `accept-incomplete`.
    AcceptIncomplete,
    /// `reject`.
    Reject,
    /// `request-mic`.
    RequestMic,
}

impl NegState {
    fn value(self) -> u32 {
        match self {
            Self::AcceptCompleted => 0,
            Self::AcceptIncomplete => 1,
            Self::Reject => 2,
            Self::RequestMic => 3,
        }
    }

    fn from_value(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::AcceptCompleted),
            1 => Ok(Self::AcceptIncomplete),
            2 => Ok(Self::Reject),
            3 => Ok(Self::RequestMic),
            actual => Err(Error::InvalidNegState(actual)),
        }
    }
}

/// SPNEGO NegTokenInit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegTokenInit {
    /// Offered mechanism OIDs.
    pub mech_types: Vec<ObjectIdentifier>,
    /// Optional DER BIT STRING contents, including the unused-bit count byte.
    pub req_flags: Option<Vec<u8>>,
    /// Optional mechanism token bytes.
    pub mech_token: Option<Vec<u8>>,
    /// Optional mechanism list MIC bytes.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenInit {
    /// Build a NegTokenInit that offers Kerberos 5 and carries a KRB5 mech
    /// token.
    pub fn krb5(mech_token: Vec<u8>) -> Self {
        Self {
            mech_types: vec![ObjectIdentifier::krb5()],
            req_flags: None,
            mech_token: Some(mech_token),
            mech_list_mic: None,
        }
    }

    /// Encode this NegTokenInit as a SPNEGO negotiation token choice.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.mech_types.is_empty() {
            return Err(Error::MissingMechTypes);
        }

        let mut fields = Vec::new();
        let mut mech_types = Vec::new();
        for oid in &self.mech_types {
            mech_types.extend_from_slice(&encode_oid(oid)?);
        }
        fields.extend_from_slice(&encode_explicit(
            TAG_CONTEXT_0,
            &encode_tlv(TAG_SEQUENCE, &mech_types),
        ));

        if let Some(req_flags) = &self.req_flags {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_1,
                &encode_tlv(TAG_BIT_STRING, req_flags),
            ));
        }
        if let Some(mech_token) = &self.mech_token {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_2,
                &encode_tlv(TAG_OCTET_STRING, mech_token),
            ));
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_3,
                &encode_tlv(TAG_OCTET_STRING, mech_list_mic),
            ));
        }

        Ok(encode_explicit(
            TAG_CONTEXT_0,
            &encode_tlv(TAG_SEQUENCE, &fields),
        ))
    }

    /// Decode a NegTokenInit from a SPNEGO negotiation token choice.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        match NegotiationToken::decode(bytes)? {
            NegotiationToken::Init(token) => Ok(token),
            NegotiationToken::Resp(_) => Err(Error::WrongNegotiationToken {
                expected: "NegTokenInit",
                actual: "NegTokenResp",
            }),
        }
    }

    /// Return the first KRB5 AP-REQ carried by this token.
    pub fn krb5_ap_req(&self) -> Result<Vec<u8>, Error> {
        ensure_kerberos_mechanism(&self.mech_types)?;
        let token = self.mech_token.as_deref().ok_or(Error::MissingMechToken)?;
        let krb5 = Krb5MechToken::decode(token)?;
        if krb5.token_id != Krb5TokenId::ApReq {
            return Err(Error::MissingApReq);
        }
        Ok(krb5.message)
    }
}

/// SPNEGO NegTokenResp / NegTokenTarg.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegTokenResp {
    /// Optional negotiation state.
    pub neg_state: Option<NegState>,
    /// Optional selected mechanism OID.
    pub supported_mech: Option<ObjectIdentifier>,
    /// Optional response token bytes.
    pub response_token: Option<Vec<u8>>,
    /// Optional mechanism list MIC bytes.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenResp {
    /// Build an `accept-completed` response selecting Kerberos 5.
    pub fn accept_completed() -> Self {
        Self {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: Some(ObjectIdentifier::krb5()),
            response_token: None,
            mech_list_mic: None,
        }
    }

    /// Build an `accept-incomplete` response selecting Kerberos 5.
    pub fn accept_incomplete_krb5() -> Self {
        Self {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(ObjectIdentifier::krb5()),
            response_token: None,
            mech_list_mic: None,
        }
    }

    /// Build a rejection response.
    pub fn reject() -> Self {
        Self {
            neg_state: Some(NegState::Reject),
            supported_mech: None,
            response_token: None,
            mech_list_mic: None,
        }
    }

    /// Attach a mechanism response token.
    pub fn with_response_token(mut self, response_token: Vec<u8>) -> Self {
        self.response_token = Some(response_token);
        self
    }

    /// Encode this NegTokenResp as a SPNEGO negotiation token choice.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut fields = Vec::new();
        if let Some(neg_state) = self.neg_state {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_0,
                &encode_tlv(TAG_ENUMERATED, &encode_u32(neg_state.value())),
            ));
        }
        if let Some(supported_mech) = &self.supported_mech {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_1,
                &encode_oid(supported_mech)?,
            ));
        }
        if let Some(response_token) = &self.response_token {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_2,
                &encode_tlv(TAG_OCTET_STRING, response_token),
            ));
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_3,
                &encode_tlv(TAG_OCTET_STRING, mech_list_mic),
            ));
        }
        Ok(encode_explicit(
            TAG_CONTEXT_1,
            &encode_tlv(TAG_SEQUENCE, &fields),
        ))
    }

    /// Decode a NegTokenResp from a SPNEGO negotiation token choice.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        match NegotiationToken::decode(bytes)? {
            NegotiationToken::Init(_) => Err(Error::WrongNegotiationToken {
                expected: "NegTokenResp",
                actual: "NegTokenInit",
            }),
            NegotiationToken::Resp(token) => Ok(token),
        }
    }
}

/// SPNEGO negotiation token choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegotiationToken {
    /// NegTokenInit.
    Init(NegTokenInit),
    /// NegTokenResp / NegTokenTarg.
    Resp(NegTokenResp),
}

impl NegotiationToken {
    /// Decode a SPNEGO negotiation token choice.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut outer = DerReader::new(bytes);
        let choice = outer.read_tlv()?;
        outer.finish()?;
        decode_negotiation_choice(choice)
    }

    /// Encode this negotiation token choice.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => token.encode(),
            Self::Resp(token) => token.encode(),
        }
    }
}

/// Full SPNEGO GSS context token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpnegoToken {
    /// Initial context token with SPNEGO OID and NegTokenInit.
    Init(NegTokenInit),
    /// Bare NegTokenResp response token.
    Resp(NegTokenResp),
}

impl SpnegoToken {
    /// Decode a full SPNEGO context token.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyInput);
        }

        if bytes[0] == TAG_APPLICATION_0 {
            let mut outer = DerReader::new(bytes);
            let token = outer.read_tlv()?;
            outer.finish()?;

            let mut content = DerReader::new(token.value);
            let oid = decode_oid_tlv(content.read_tlv()?)?;
            if oid != ObjectIdentifier::spnego() {
                return Err(Error::UnexpectedSpnegoOid(oid));
            }
            let negotiation = content.remaining();
            match NegotiationToken::decode(negotiation)? {
                NegotiationToken::Init(token) => Ok(Self::Init(token)),
                NegotiationToken::Resp(_) => Err(Error::WrongNegotiationToken {
                    expected: "NegTokenInit",
                    actual: "NegTokenResp",
                }),
            }
        } else {
            match NegotiationToken::decode(bytes)? {
                NegotiationToken::Init(token) => Ok(Self::Init(token)),
                NegotiationToken::Resp(token) => Ok(Self::Resp(token)),
            }
        }
    }

    /// Encode a full SPNEGO context token.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => {
                let mut content = encode_oid(&ObjectIdentifier::spnego())?;
                content.extend_from_slice(&token.encode()?);
                Ok(encode_tlv(TAG_APPLICATION_0, &content))
            }
            Self::Resp(token) => token.encode(),
        }
    }

    /// Return the first KRB5 AP-REQ carried by this token.
    pub fn krb5_ap_req(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => token.krb5_ap_req(),
            Self::Resp(token) => {
                let mech = token
                    .supported_mech
                    .as_ref()
                    .ok_or(Error::MissingMechTypes)?;
                ensure_kerberos_mechanism(std::slice::from_ref(mech))?;
                let response = token
                    .response_token
                    .as_deref()
                    .ok_or(Error::MissingMechToken)?;
                let krb5 = Krb5MechToken::decode(response)?;
                if krb5.token_id != Krb5TokenId::ApReq {
                    return Err(Error::MissingApReq);
                }
                Ok(krb5.message)
            }
        }
    }
}

/// Validated SPNEGO service context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedContext {
    /// Validated AP-REQ details.
    pub ap_req: ValidatedApReq,
}

impl AcceptedContext {
    /// Build a `WWW-Authenticate` header containing an AP-REP response token.
    pub fn ap_rep_response_header_with_confounder(
        &self,
        confounder: &[u8],
        options: ApRepOptions,
    ) -> Result<String, Error> {
        let ap_rep = self
            .ap_req
            .build_ap_rep_with_confounder(confounder, options)?;
        let krb5_token = Krb5MechToken::ap_rep(ap_rep).encode()?;
        response_token_header(NegTokenResp::accept_completed().with_response_token(krb5_token))
    }
}

/// Validate a SPNEGO HTTP `Authorization` header through a service validator.
pub fn accept_sec_context_header(
    validator: &mut ServiceValidator<'_>,
    header: &str,
) -> Result<AcceptedContext, Error> {
    let token = parse_negotiate_header(header)?;
    let ap_req = token.krb5_ap_req()?;
    Ok(AcceptedContext {
        ap_req: validator.validate_ap_req(&ap_req)?,
    })
}

/// Decode an HTTP `Negotiate` header into a SPNEGO token.
pub fn parse_negotiate_header(header: &str) -> Result<SpnegoToken, Error> {
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    let encoded = parts.next().ok_or(Error::InvalidNegotiateHeader)?;
    if !scheme.eq_ignore_ascii_case(HTTP_NEGOTIATE) || encoded.trim().is_empty() {
        return Err(Error::InvalidNegotiateHeader);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(Error::Base64)?;
    SpnegoToken::decode(&bytes)
}

/// Encode a SPNEGO token as an HTTP `Negotiate` header value.
pub fn negotiate_header(token: &SpnegoToken) -> Result<String, Error> {
    Ok(format!(
        "{HTTP_NEGOTIATE} {}",
        base64::engine::general_purpose::STANDARD.encode(token.encode()?)
    ))
}

/// Header value used to start SPNEGO negotiation.
pub fn challenge_header() -> &'static str {
    HTTP_NEGOTIATE
}

/// Header value for a Kerberos `accept-completed` SPNEGO response.
pub fn accept_completed_header() -> Result<String, Error> {
    response_token_header(NegTokenResp::accept_completed())
}

/// Header value for a Kerberos `accept-incomplete` SPNEGO response.
pub fn accept_incomplete_krb5_header() -> Result<String, Error> {
    response_token_header(NegTokenResp::accept_incomplete_krb5())
}

/// Header value for a SPNEGO rejection response.
pub fn reject_header() -> Result<String, Error> {
    response_token_header(NegTokenResp::reject())
}

fn response_token_header(token: NegTokenResp) -> Result<String, Error> {
    Ok(format!(
        "{HTTP_NEGOTIATE} {}",
        base64::engine::general_purpose::STANDARD.encode(token.encode()?)
    ))
}

/// Create a SPNEGO authenticator checksum buffer for GSS context flags.
pub fn authenticator_checksum(flags: &[u32]) -> Vec<u8> {
    let mut checksum = vec![0; 24];
    checksum[..4].copy_from_slice(&16u32.to_le_bytes());
    for flag in flags {
        if *flag == CONTEXT_FLAG_DELEG && checksum.len() < 28 {
            checksum.resize(28, 0);
        }
        let mut current = u32::from_le_bytes(
            checksum[20..24]
                .try_into()
                .expect("checksum buffer has the context flags slot"),
        );
        current |= *flag;
        checksum[20..24].copy_from_slice(&current.to_le_bytes());
    }
    checksum
}

/// SPNEGO/GSS token processing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Input was absent.
    #[error("input is empty")]
    EmptyInput,

    /// DER input ended before a complete value could be read.
    #[error("truncated DER value")]
    TruncatedDer,

    /// DER used an unsupported high-tag-number form.
    #[error("high-tag-number DER form is not supported")]
    HighTagNumber,

    /// DER used an unsupported indefinite length.
    #[error("indefinite DER length is not supported")]
    IndefiniteLength,

    /// DER length exceeds the remaining input.
    #[error("DER length exceeds remaining input")]
    LengthExceedsInput,

    /// DER value used an unexpected tag.
    #[error("unexpected DER tag: expected 0x{expected:02x}, got 0x{actual:02x}")]
    UnexpectedTag {
        /// Expected one-byte tag.
        expected: u8,
        /// Actual one-byte tag.
        actual: u8,
    },

    /// DER contained trailing bytes after the expected value.
    #[error("trailing DER data")]
    TrailingData,

    /// OID arcs were invalid.
    #[error("invalid object identifier")]
    InvalidOid,

    /// OID base-128 encoding was malformed.
    #[error("invalid object identifier encoding")]
    InvalidOidEncoding,

    /// SPNEGO OID did not match `1.3.6.1.5.5.2`.
    #[error("unexpected SPNEGO OID: {0:?}")]
    UnexpectedSpnegoOid(ObjectIdentifier),

    /// The mechanism OID is not a supported Kerberos mechanism.
    #[error("unsupported mechanism OID: {0:?}")]
    UnsupportedMechanism(ObjectIdentifier),

    /// KRB5 token ID was unknown.
    #[error("unknown KRB5 token ID: {0:02x?}")]
    UnknownKrb5TokenId([u8; 2]),

    /// KRB5 token omitted its Kerberos message bytes.
    #[error("KRB5 token does not contain a Kerberos message")]
    MissingKerberosMessage,

    /// NegTokenInit omitted the mechanism list.
    #[error("NegTokenInit does not contain any mechanism types")]
    MissingMechTypes,

    /// SPNEGO token omitted the mechanism token.
    #[error("SPNEGO token does not contain a mechanism token")]
    MissingMechToken,

    /// SPNEGO token does not carry an AP-REQ.
    #[error("SPNEGO token does not carry a KRB5 AP-REQ")]
    MissingApReq,

    /// A negotiation token had the wrong CHOICE variant.
    #[error("expected {expected}, got {actual}")]
    WrongNegotiationToken {
        /// Expected variant.
        expected: &'static str,
        /// Actual variant.
        actual: &'static str,
    },

    /// SPNEGO negotiation state was invalid.
    #[error("invalid SPNEGO negState: {0}")]
    InvalidNegState(u32),

    /// INTEGER/ENUMERATED value was not supported.
    #[error("invalid DER integer value")]
    InvalidInteger,

    /// HTTP header was not a usable `Negotiate` value.
    #[error("invalid Negotiate header")]
    InvalidNegotiateHeader,

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(base64::DecodeError),

    /// Service AP-REQ validation failed.
    #[error("service validation error: {0}")]
    Service(#[from] crate::service::Error),
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_tlv(&mut self) -> Result<Tlv<'a>, Error> {
        if self.offset >= self.bytes.len() {
            return Err(Error::TruncatedDer);
        }

        let tag = self.bytes[self.offset];
        self.offset += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::HighTagNumber);
        }
        let length = self.read_len()?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::LengthExceedsInput)?;
        if end > self.bytes.len() {
            return Err(Error::LengthExceedsInput);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(Tlv { tag, value })
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::TruncatedDer)?;
        if end > self.bytes.len() {
            return Err(Error::TruncatedDer);
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn finish(&self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    fn read_len(&mut self) -> Result<usize, Error> {
        if self.offset >= self.bytes.len() {
            return Err(Error::TruncatedDer);
        }
        let first = self.bytes[self.offset];
        self.offset += 1;
        if first & 0x80 == 0 {
            return Ok(first.into());
        }

        let count = (first & 0x7f) as usize;
        if count == 0 {
            return Err(Error::IndefiniteLength);
        }
        if count > std::mem::size_of::<usize>() || self.offset + count > self.bytes.len() {
            return Err(Error::LengthExceedsInput);
        }

        let mut length = 0usize;
        for byte in &self.bytes[self.offset..self.offset + count] {
            length = (length << 8) | usize::from(*byte);
        }
        self.offset += count;
        Ok(length)
    }
}

fn decode_negotiation_choice(choice: Tlv<'_>) -> Result<NegotiationToken, Error> {
    match choice.tag {
        TAG_CONTEXT_0 => Ok(NegotiationToken::Init(decode_neg_token_init(choice.value)?)),
        TAG_CONTEXT_1 => Ok(NegotiationToken::Resp(decode_neg_token_resp(choice.value)?)),
        actual => Err(Error::UnexpectedTag {
            expected: TAG_CONTEXT_0,
            actual,
        }),
    }
}

fn decode_neg_token_init(bytes: &[u8]) -> Result<NegTokenInit, Error> {
    let sequence = read_single_tlv(bytes, TAG_SEQUENCE)?;
    let mut fields = DerReader::new(sequence.value);
    let mut mech_types = None;
    let mut req_flags = None;
    let mut mech_token = None;
    let mut mech_list_mic = None;

    while !fields.remaining().is_empty() {
        let field = fields.read_tlv()?;
        match field.tag {
            TAG_CONTEXT_0 => {
                let sequence = read_single_tlv(field.value, TAG_SEQUENCE)?;
                let mut oid_reader = DerReader::new(sequence.value);
                let mut oids = Vec::new();
                while !oid_reader.remaining().is_empty() {
                    oids.push(decode_oid_tlv(oid_reader.read_tlv()?)?);
                }
                mech_types = Some(oids);
            }
            TAG_CONTEXT_1 => {
                req_flags = Some(read_single_tlv(field.value, TAG_BIT_STRING)?.value.to_vec());
            }
            TAG_CONTEXT_2 => {
                mech_token = Some(
                    read_single_tlv(field.value, TAG_OCTET_STRING)?
                        .value
                        .to_vec(),
                );
            }
            TAG_CONTEXT_3 => {
                mech_list_mic = Some(
                    read_single_tlv(field.value, TAG_OCTET_STRING)?
                        .value
                        .to_vec(),
                );
            }
            actual => {
                return Err(Error::UnexpectedTag {
                    expected: TAG_CONTEXT_0,
                    actual,
                });
            }
        }
    }

    let mech_types = mech_types.ok_or(Error::MissingMechTypes)?;
    if mech_types.is_empty() {
        return Err(Error::MissingMechTypes);
    }
    Ok(NegTokenInit {
        mech_types,
        req_flags,
        mech_token,
        mech_list_mic,
    })
}

fn decode_neg_token_resp(bytes: &[u8]) -> Result<NegTokenResp, Error> {
    let sequence = read_single_tlv(bytes, TAG_SEQUENCE)?;
    let mut fields = DerReader::new(sequence.value);
    let mut neg_state = None;
    let mut supported_mech = None;
    let mut response_token = None;
    let mut mech_list_mic = None;

    while !fields.remaining().is_empty() {
        let field = fields.read_tlv()?;
        match field.tag {
            TAG_CONTEXT_0 => {
                let enumerated = read_single_tlv(field.value, TAG_ENUMERATED)?;
                neg_state = Some(NegState::from_value(decode_u32(enumerated.value)?)?);
            }
            TAG_CONTEXT_1 => {
                supported_mech = Some(decode_oid_tlv(read_single_tlv(
                    field.value,
                    TAG_OBJECT_IDENTIFIER,
                )?)?);
            }
            TAG_CONTEXT_2 => {
                response_token = Some(
                    read_single_tlv(field.value, TAG_OCTET_STRING)?
                        .value
                        .to_vec(),
                );
            }
            TAG_CONTEXT_3 => {
                mech_list_mic = Some(
                    read_single_tlv(field.value, TAG_OCTET_STRING)?
                        .value
                        .to_vec(),
                );
            }
            actual => {
                return Err(Error::UnexpectedTag {
                    expected: TAG_CONTEXT_0,
                    actual,
                });
            }
        }
    }

    Ok(NegTokenResp {
        neg_state,
        supported_mech,
        response_token,
        mech_list_mic,
    })
}

fn read_single_tlv(bytes: &[u8], expected_tag: u8) -> Result<Tlv<'_>, Error> {
    let mut reader = DerReader::new(bytes);
    let tlv = reader.read_tlv()?;
    reader.finish()?;
    if tlv.tag != expected_tag {
        return Err(Error::UnexpectedTag {
            expected: expected_tag,
            actual: tlv.tag,
        });
    }
    Ok(tlv)
}

fn decode_oid_tlv(tlv: Tlv<'_>) -> Result<ObjectIdentifier, Error> {
    if tlv.tag != TAG_OBJECT_IDENTIFIER {
        return Err(Error::UnexpectedTag {
            expected: TAG_OBJECT_IDENTIFIER,
            actual: tlv.tag,
        });
    }
    decode_oid_value(tlv.value)
}

fn decode_oid_value(value: &[u8]) -> Result<ObjectIdentifier, Error> {
    if value.is_empty() {
        return Err(Error::InvalidOidEncoding);
    }

    let first = value[0];
    let first_arc = u32::from(first / 40);
    let second_arc = u32::from(first % 40);
    let mut arcs = vec![first_arc, second_arc];
    let mut idx = 1;
    while idx < value.len() {
        let mut arc = 0u32;
        loop {
            if idx >= value.len() {
                return Err(Error::InvalidOidEncoding);
            }
            let byte = value[idx];
            idx += 1;
            arc = arc.checked_shl(7).ok_or(Error::InvalidOidEncoding)? | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
        }
        arcs.push(arc);
    }

    ObjectIdentifier::from_arcs(arcs)
}

fn validate_oid_arcs(arcs: &[u32]) -> Result<(), Error> {
    if arcs.len() < 2 {
        return Err(Error::InvalidOid);
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(Error::InvalidOid);
    }
    Ok(())
}

fn encode_oid(oid: &ObjectIdentifier) -> Result<Vec<u8>, Error> {
    validate_oid_arcs(oid.arcs())?;
    let mut value = Vec::new();
    let first = oid.arcs()[0]
        .checked_mul(40)
        .and_then(|base| base.checked_add(oid.arcs()[1]))
        .ok_or(Error::InvalidOid)?;
    encode_base128(first, &mut value);
    for arc in &oid.arcs()[2..] {
        encode_base128(*arc, &mut value);
    }
    Ok(encode_tlv(TAG_OBJECT_IDENTIFIER, &value))
}

fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut stack = [0u8; 5];
    let mut len = 1;
    stack[4] = (value & 0x7f) as u8;
    value >>= 7;
    while value > 0 {
        len += 1;
        stack[5 - len] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }
    out.extend_from_slice(&stack[5 - len..]);
}

fn decode_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(Error::InvalidInteger);
    }
    if bytes[0] & 0x80 != 0 {
        return Err(Error::InvalidInteger);
    }
    let mut value = 0u32;
    for byte in bytes {
        value = value.checked_shl(8).ok_or(Error::InvalidInteger)? | u32::from(*byte);
    }
    Ok(value)
}

fn encode_u32(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut encoded = bytes[first_nonzero..].to_vec();
    if encoded[0] & 0x80 != 0 {
        encoded.insert(0, 0);
    }
    encoded
}

fn encode_explicit(tag: u8, inner_der: &[u8]) -> Vec<u8> {
    encode_tlv(tag, inner_der)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
        return;
    }

    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short length is nonzero");
    let length_bytes = &bytes[first..];
    out.push(0x80 | length_bytes.len() as u8);
    out.extend_from_slice(length_bytes);
}

fn ensure_kerberos_mechanism(mech_types: &[ObjectIdentifier]) -> Result<(), Error> {
    if mech_types.is_empty() {
        return Err(Error::MissingMechTypes);
    }

    if mech_types
        .iter()
        .any(ObjectIdentifier::is_kerberos_mechanism)
    {
        Ok(())
    } else {
        Err(Error::UnsupportedMechanism(mech_types[0].clone()))
    }
}
