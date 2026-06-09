//! SPNEGO and GSS-API Kerberos token helpers.
//!
//! This module covers the wrapper layer around the Kerberos messages handled by
//! [`crate::client`] and [`crate::service`]: GSS-API KRB5 mech tokens, SPNEGO
//! NegTokenInit/NegTokenResp negotiation tokens, and HTTP `Negotiate` header
//! encoding/decoding.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use crate::client::{ApReqOptions, Principal, TgsRepSession, build_ap_req_with_confounder};
use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;
use crate::service::{ApRepOptions, ServiceValidator, ValidatedApReq, VerifiedApRep};

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
const TOK_ID_GSS_MIC: [u8; 2] = [0x04, 0x04];
const TOK_ID_GSS_WRAP: [u8; 2] = [0x05, 0x04];
const KRB5_PVNO: i32 = 5;
const KRB_AP_REP_MSG_TYPE: i32 = 15;
const AP_REP_ENCPART_USAGE: u32 = 12;
const GSSAPI_CHECKSUM_TYPE: i32 = 32_771;
const GSS_MIC_HEADER_LEN: usize = 16;
const GSS_WRAP_HEADER_LEN: usize = 16;
const GSS_MIC_FILLER: [u8; 5] = [0xff; 5];
const GSS_WRAP_FILLER: u8 = 0xff;

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

/// RFC4121 token flag: token was sent by the context acceptor.
pub const GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// RFC4121 token flag: token is sealed.
pub const GSS_TOKEN_FLAG_SEALED: u8 = 0x02;
/// RFC4121 token flag: token uses an acceptor subkey.
pub const GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// GSS-API acceptor seal key usage.
pub const GSSAPI_ACCEPTOR_SEAL_USAGE: u32 = 22;
/// GSS-API acceptor sign key usage.
pub const GSSAPI_ACCEPTOR_SIGN_USAGE: u32 = 23;
/// GSS-API initiator seal key usage.
pub const GSSAPI_INITIATOR_SEAL_USAGE: u32 = 24;
/// GSS-API initiator sign key usage.
pub const GSSAPI_INITIATOR_SIGN_USAGE: u32 = 25;

/// RFC4121 GSS-API MIC token.
///
/// The payload is authenticated but not transmitted in the token bytes, matching
/// gokrb5's MIC token model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MicToken {
    /// RFC4121 token flags.
    pub flags: u8,
    /// Sender sequence number.
    pub snd_seq_num: u64,
    /// Payload bytes authenticated by this MIC token. Not encoded on the wire.
    pub payload: Option<Vec<u8>>,
    /// Token checksum.
    pub checksum: Option<Vec<u8>>,
}

impl MicToken {
    /// Build a MIC token with no payload or checksum.
    pub fn new(flags: u8, snd_seq_num: u64) -> Self {
        Self {
            flags,
            snd_seq_num,
            payload: None,
            checksum: None,
        }
    }

    /// Decode a MIC token.
    pub fn decode(bytes: &[u8], expect_from_acceptor: bool) -> Result<Self, Error> {
        if bytes.len() < GSS_MIC_HEADER_LEN {
            return Err(Error::GssTokenTooShort {
                minimum: GSS_MIC_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        validate_gss_token_id(&bytes[..2], TOK_ID_GSS_MIC)?;
        validate_gss_sender(bytes[2], expect_from_acceptor)?;
        if bytes[3..8] != GSS_MIC_FILLER {
            return Err(Error::InvalidGssFiller);
        }

        Ok(Self {
            flags: bytes[2],
            snd_seq_num: u64::from_be_bytes(
                bytes[8..16].try_into().expect("slice length checked above"),
            ),
            payload: None,
            checksum: Some(bytes[GSS_MIC_HEADER_LEN..].to_vec()),
        })
    }

    /// Encode this MIC token.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let checksum = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        let mut bytes = self.checksum_header();
        bytes.extend_from_slice(checksum);
        Ok(bytes)
    }

    /// Set the authenticated payload bytes.
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    /// Compute and set this token's checksum.
    pub fn set_checksum(&mut self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        if self.checksum.is_some() {
            return Err(Error::GssChecksumAlreadySet);
        }
        self.checksum = Some(self.compute_checksum(key, key_usage)?);
        Ok(())
    }

    /// Verify this token's checksum.
    pub fn verify(&self, key: &EncryptionKey, key_usage: u32) -> Result<bool, Error> {
        let expected = self.compute_checksum(key, key_usage)?;
        let actual = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if !constant_time_eq(&expected, actual) {
            return Err(Error::GssChecksumMismatch);
        }
        Ok(true)
    }

    /// Build an initiator MIC token and compute its checksum.
    pub fn new_initiator(payload: impl Into<Vec<u8>>, key: &EncryptionKey) -> Result<Self, Error> {
        let mut token = Self {
            flags: 0,
            snd_seq_num: 0,
            payload: Some(payload.into()),
            checksum: None,
        };
        token.set_checksum(key, GSSAPI_INITIATOR_SIGN_USAGE)?;
        Ok(token)
    }

    fn compute_checksum(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = Vec::with_capacity(payload.len() + GSS_MIC_HEADER_LEN);
        data.extend_from_slice(payload);
        data.extend_from_slice(&self.checksum_header());

        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        etype
            .checksum(&key.value, &data, key_usage)
            .map_err(Error::Crypto)
    }

    fn checksum_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(GSS_MIC_HEADER_LEN);
        header.extend_from_slice(&TOK_ID_GSS_MIC);
        header.push(self.flags);
        header.extend_from_slice(&GSS_MIC_FILLER);
        header.extend_from_slice(&self.snd_seq_num.to_be_bytes());
        header
    }
}

/// RFC4121 GSS-API Wrap token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapToken {
    /// RFC4121 token flags.
    pub flags: u8,
    /// Extra count. This is the checksum length for unsealed tokens and the
    /// filler length for sealed tokens.
    pub ec: u16,
    /// Right rotation count.
    pub rrc: u16,
    /// Sender sequence number.
    pub snd_seq_num: u64,
    /// Wrapped payload bytes.
    pub payload: Option<Vec<u8>>,
    /// Token checksum for unsealed tokens.
    pub checksum: Option<Vec<u8>>,
    /// Encrypted token body for sealed tokens, stored exactly as transmitted
    /// after the 16-byte Wrap header, including any right rotation.
    pub encrypted_body: Option<Vec<u8>>,
}

impl WrapToken {
    /// Build a wrap token with no payload or checksum.
    pub fn new(flags: u8, snd_seq_num: u64) -> Self {
        Self {
            flags,
            ec: 0,
            rrc: 0,
            snd_seq_num,
            payload: None,
            checksum: None,
            encrypted_body: None,
        }
    }

    /// Decode a wrap token.
    ///
    /// Sealed tokens can be parsed without a key, but their payload is only
    /// available after [`Self::decrypt_payload`] or [`Self::decrypt_and_set_payload`].
    pub fn decode(bytes: &[u8], expect_from_acceptor: bool) -> Result<Self, Error> {
        if bytes.len() < GSS_WRAP_HEADER_LEN {
            return Err(Error::GssTokenTooShort {
                minimum: GSS_WRAP_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        validate_gss_token_id(&bytes[..2], TOK_ID_GSS_WRAP)?;
        validate_gss_sender(bytes[2], expect_from_acceptor)?;
        if bytes[3] != GSS_WRAP_FILLER {
            return Err(Error::InvalidGssFiller);
        }

        let ec = u16::from_be_bytes(bytes[4..6].try_into().expect("slice length checked above"));
        let rrc = u16::from_be_bytes(bytes[6..8].try_into().expect("slice length checked above"));
        let snd_seq_num =
            u64::from_be_bytes(bytes[8..16].try_into().expect("slice length checked above"));
        if bytes[2] & GSS_TOKEN_FLAG_SEALED != 0 {
            let encrypted_body = bytes[GSS_WRAP_HEADER_LEN..].to_vec();
            if encrypted_body.is_empty() {
                return Err(Error::MissingGssEncryptedBody);
            }
            return Ok(Self {
                flags: bytes[2],
                ec,
                rrc,
                snd_seq_num,
                payload: None,
                checksum: None,
                encrypted_body: Some(encrypted_body),
            });
        }

        let checksum_len = usize::from(ec);
        if checksum_len > bytes.len() - GSS_WRAP_HEADER_LEN {
            return Err(Error::InconsistentWrapChecksumLength {
                token_len: bytes.len(),
                checksum_len,
            });
        }

        let checksum_start = bytes.len() - checksum_len;
        Ok(Self {
            flags: bytes[2],
            ec,
            rrc,
            snd_seq_num,
            payload: Some(bytes[GSS_WRAP_HEADER_LEN..checksum_start].to_vec()),
            checksum: Some(bytes[checksum_start..].to_vec()),
            encrypted_body: None,
        })
    }

    /// Encode this wrap token.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.is_sealed() {
            let encrypted_body = self
                .encrypted_body
                .as_ref()
                .ok_or(Error::MissingGssEncryptedBody)?;
            let mut bytes = self.header(self.rrc);
            bytes.extend_from_slice(encrypted_body);
            return Ok(bytes);
        }

        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let checksum = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if checksum.len() != usize::from(self.ec) {
            return Err(Error::InvalidGssChecksumLength {
                expected: usize::from(self.ec),
                actual: checksum.len(),
            });
        }

        let mut bytes = Vec::with_capacity(GSS_WRAP_HEADER_LEN + payload.len() + checksum.len());
        bytes.extend_from_slice(&self.header(self.rrc));
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(checksum);
        Ok(bytes)
    }

    /// Set wrapped payload bytes.
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    /// Compute and set this token's checksum.
    pub fn set_checksum(&mut self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        if self.checksum.is_some() {
            return Err(Error::GssChecksumAlreadySet);
        }
        if self.is_sealed() {
            return Err(Error::SealedGssTokenNeedsEncryption);
        }
        let checksum = self.compute_checksum(key, key_usage)?;
        if self.ec == 0 {
            self.ec =
                u16::try_from(checksum.len()).map_err(|_| Error::InvalidGssChecksumLength {
                    expected: usize::from(u16::MAX),
                    actual: checksum.len(),
                })?;
        }
        self.checksum = Some(checksum);
        Ok(())
    }

    /// Verify this token's checksum.
    pub fn verify(&self, key: &EncryptionKey, key_usage: u32) -> Result<bool, Error> {
        if self.is_sealed() {
            self.decrypt_payload(key, key_usage)?;
            return Ok(true);
        }

        let expected = self.compute_checksum(key, key_usage)?;
        let actual = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if !constant_time_eq(&expected, actual) {
            return Err(Error::GssChecksumMismatch);
        }
        Ok(true)
    }

    /// Build an initiator wrap token and compute its checksum.
    pub fn new_initiator(payload: impl Into<Vec<u8>>, key: &EncryptionKey) -> Result<Self, Error> {
        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        let mut token = Self {
            flags: 0,
            ec: u16::try_from(etype.hmac_len()).map_err(|_| Error::InvalidGssChecksumLength {
                expected: usize::from(u16::MAX),
                actual: etype.hmac_len(),
            })?,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(payload.into()),
            checksum: None,
            encrypted_body: None,
        };
        token.set_checksum(key, GSSAPI_INITIATOR_SEAL_USAGE)?;
        Ok(token)
    }

    /// Build an initiator sealed wrap token with a random confounder.
    pub fn new_initiator_sealed(
        payload: impl Into<Vec<u8>>,
        key: &EncryptionKey,
    ) -> Result<Self, Error> {
        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        Self::new_initiator_sealed_with_confounder(payload, key, &confounder)
    }

    /// Build an initiator sealed wrap token with an explicit confounder.
    pub fn new_initiator_sealed_with_confounder(
        payload: impl Into<Vec<u8>>,
        key: &EncryptionKey,
        confounder: &[u8],
    ) -> Result<Self, Error> {
        let mut token = Self {
            flags: GSS_TOKEN_FLAG_SEALED,
            ec: 0,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(payload.into()),
            checksum: None,
            encrypted_body: None,
        };
        token.encrypt_payload_with_confounder(key, GSSAPI_INITIATOR_SEAL_USAGE, confounder)?;
        Ok(token)
    }

    /// Encrypt this token's payload as a sealed RFC4121 Wrap token.
    pub fn encrypt_payload_with_confounder(
        &mut self,
        key: &EncryptionKey,
        key_usage: u32,
        confounder: &[u8],
    ) -> Result<(), Error> {
        if self.encrypted_body.is_some() {
            return Err(Error::GssEncryptedBodyAlreadySet);
        }

        self.flags |= GSS_TOKEN_FLAG_SEALED;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        let mut plaintext = Vec::with_capacity(payload.len() + usize::from(self.ec) + 16);
        plaintext.extend_from_slice(payload);
        plaintext.resize(plaintext.len() + usize::from(self.ec), 0);
        plaintext.extend_from_slice(&self.header(0));

        let encrypted =
            etype.encrypt_message_with_confounder(&key.value, &plaintext, key_usage, confounder)?;
        self.encrypted_body = Some(rotate_right(&encrypted, usize::from(self.rrc)));
        self.checksum = None;
        Ok(())
    }

    /// Decrypt and return the payload of a sealed Wrap token.
    pub fn decrypt_payload(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        if !self.is_sealed() {
            return Err(Error::GssTokenNotSealed);
        }

        let encrypted_body = self
            .encrypted_body
            .as_ref()
            .ok_or(Error::MissingGssEncryptedBody)?;
        let encrypted = rotate_left(encrypted_body, usize::from(self.rrc));
        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        let plaintext = etype.decrypt_message(&key.value, &encrypted, key_usage)?;

        let trailer_len = GSS_WRAP_HEADER_LEN + usize::from(self.ec);
        if plaintext.len() < trailer_len {
            return Err(Error::GssDecryptedTokenTooShort {
                minimum: trailer_len,
                actual: plaintext.len(),
            });
        }

        let header_start = plaintext.len() - GSS_WRAP_HEADER_LEN;
        let embedded_header = &plaintext[header_start..];
        let expected_header = self.header(0);
        if embedded_header != expected_header {
            return Err(Error::InvalidGssEncryptedHeader);
        }

        let payload_len = plaintext.len() - trailer_len;
        Ok(plaintext[..payload_len].to_vec())
    }

    /// Decrypt a sealed token and store its payload on this value.
    pub fn decrypt_and_set_payload(
        &mut self,
        key: &EncryptionKey,
        key_usage: u32,
    ) -> Result<&[u8], Error> {
        let payload = self.decrypt_payload(key, key_usage)?;
        self.payload = Some(payload);
        Ok(self
            .payload
            .as_deref()
            .expect("payload was set immediately above"))
    }

    /// Whether this Wrap token has the RFC4121 sealed/confidentiality flag.
    pub fn is_sealed(&self) -> bool {
        self.flags & GSS_TOKEN_FLAG_SEALED != 0
    }

    fn compute_checksum(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = Vec::with_capacity(payload.len() + GSS_WRAP_HEADER_LEN);
        data.extend_from_slice(payload);
        data.extend_from_slice(&wrap_checksum_header(self.flags, self.snd_seq_num));

        let etype =
            KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
        etype
            .checksum(&key.value, &data, key_usage)
            .map_err(Error::Crypto)
    }

    fn header(&self, rrc: u16) -> Vec<u8> {
        wrap_header(self.flags, self.ec, rrc, self.snd_seq_num)
    }
}

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

/// Options for building a client SPNEGO AP-REQ initiator token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiatorContextOptions {
    /// GSS-API context flags to place in the authenticator checksum.
    pub context_flags: Vec<u32>,
    /// AP-REQ option bit string.
    pub ap_option_bits: u32,
    /// Optional client-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    ///
    /// [`init_sec_context`] fills a random gokrb5-compatible sequence number
    /// when this is absent. [`init_sec_context_with_confounder`] preserves the
    /// explicit value so tests can remain deterministic.
    pub sequence_number: Option<u32>,
}

impl InitiatorContextOptions {
    /// Construct options matching gokrb5's default HTTP SPNEGO flags.
    pub fn new() -> Self {
        Self {
            context_flags: vec![CONTEXT_FLAG_INTEG, CONTEXT_FLAG_CONF],
            ap_option_bits: 0,
            subkey: None,
            sequence_number: None,
        }
    }

    /// Override GSS-API context flags.
    pub fn with_context_flags(mut self, context_flags: impl Into<Vec<u32>>) -> Self {
        self.context_flags = context_flags.into();
        self
    }

    /// Override AP-REQ option bits.
    pub fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
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

impl Default for InitiatorContextOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Built client SPNEGO initiator context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiatorContext {
    /// ASN.1 AP-REQ message.
    pub ap_req: rasn_kerberos::ApReq,
    /// DER-encoded AP-REQ bytes.
    pub ap_req_der: Vec<u8>,
    /// KRB5 mech token carrying the AP-REQ.
    pub krb5_token: Krb5MechToken,
    /// SPNEGO NegTokenInit context token.
    pub spnego_token: SpnegoToken,
    /// HTTP `Authorization` header value.
    pub header: String,
    /// Client principal placed in the authenticator.
    pub client: Principal,
    /// Service principal from the ticket.
    pub service: Principal,
    /// Service-ticket session key used for AP-REP verification.
    pub session_key: EncryptionKey,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional client sequence number supplied in the authenticator.
    pub sequence_number: Option<u32>,
}

impl InitiatorContext {
    /// Verify an AP-REP wrapped in a SPNEGO `Negotiate` response header.
    pub fn verify_ap_rep_response_header(&self, header: &str) -> Result<VerifiedApRep, Error> {
        let token = parse_negotiate_header(header)?;
        let response = match token {
            SpnegoToken::Resp(response) => response,
            SpnegoToken::Init(_) => {
                return Err(Error::WrongNegotiationToken {
                    expected: "NegTokenResp",
                    actual: "NegTokenInit",
                });
            }
        };
        let response_token = response.response_token.ok_or(Error::MissingMechToken)?;
        let krb5 = Krb5MechToken::decode(&response_token)?;
        if krb5.token_id != Krb5TokenId::ApRep {
            return Err(Error::MissingApRep);
        }
        self.verify_ap_rep(&krb5.message)
    }

    /// Verify an AP-REP message against this initiator's AP-REQ timestamp.
    pub fn verify_ap_rep(&self, bytes: &[u8]) -> Result<VerifiedApRep, Error> {
        let ap_rep = decode::<rasn_kerberos::ApRep>("AP-REP", bytes)?;
        validate_integer("pvno", &ap_rep.pvno, KRB5_PVNO)?;
        validate_integer("msg-type", &ap_rep.msg_type, KRB_AP_REP_MSG_TYPE)?;
        let plaintext = decrypt_encrypted_data(
            ap_rep.enc_part.etype,
            &self.session_key.value,
            ap_rep.enc_part.cipher.as_ref(),
            AP_REP_ENCPART_USAGE,
        )?;
        let enc_part = decode::<rasn_kerberos::EncApRepPart>("EncApRepPart", &plaintext)?;
        let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
        let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
        let authenticator_time = ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;

        if ctime != self.authenticator_ctime || cusec != self.authenticator_cusec {
            return Err(Error::ApRepTimestampMismatch {
                expected: self.authenticator_time,
                actual: authenticator_time,
            });
        }

        Ok(VerifiedApRep {
            ctime,
            cusec,
            authenticator_time,
            subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: enc_part.seq_number,
        })
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
    pub fn ap_rep_response_header(&self, options: ApRepOptions) -> Result<String, Error> {
        let etype = KerberosEtype::from_etype_id(self.ap_req.session_key.etype)
            .ok_or(Error::UnsupportedEtype(self.ap_req.session_key.etype))?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        self.ap_rep_response_header_with_confounder(&confounder, options)
    }

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

/// Build a client SPNEGO initiator token from a TGS service-ticket session.
pub fn init_sec_context(
    service_ticket: &TgsRepSession,
    mut options: InitiatorContextOptions,
) -> Result<InitiatorContext, Error> {
    let (timestamp, cusec) = current_time()?;
    if options.sequence_number.is_none() {
        options.sequence_number = Some(random_sequence_number()?);
    }
    let etype = KerberosEtype::from_etype_id(service_ticket.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_ticket.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    init_sec_context_with_confounder(service_ticket, options, timestamp, cusec, &confounder)
}

/// Build a client SPNEGO initiator token with deterministic timestamp and confounder.
pub fn init_sec_context_with_confounder(
    service_ticket: &TgsRepSession,
    options: InitiatorContextOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<InitiatorContext, Error> {
    let ap_req_options = ApReqOptions::new()
        .with_ap_option_bits(options.ap_option_bits)
        .with_checksum(Some(rasn_kerberos::Checksum {
            r#type: GSSAPI_CHECKSUM_TYPE,
            checksum: authenticator_checksum(&options.context_flags).into(),
        }))
        .with_subkey(options.subkey.clone())
        .with_sequence_number(options.sequence_number);
    let built_ap_req =
        build_ap_req_with_confounder(service_ticket, ap_req_options, timestamp, cusec, confounder)
            .map_err(client_error_to_spnego)?;
    let ap_req_der = built_ap_req.der.clone();
    let krb5_token = Krb5MechToken::ap_req(ap_req_der.clone());
    let krb5_token_der = krb5_token.encode()?;
    let spnego_token = SpnegoToken::Init(NegTokenInit::krb5(krb5_token_der));
    let header = negotiate_header(&spnego_token)?;

    Ok(InitiatorContext {
        ap_req: built_ap_req.message,
        ap_req_der,
        krb5_token,
        spnego_token,
        header,
        client: built_ap_req.client,
        service: built_ap_req.service,
        session_key: built_ap_req.session_key,
        authenticator_ctime: built_ap_req.authenticator_ctime,
        authenticator_cusec: built_ap_req.authenticator_cusec,
        authenticator_time: built_ap_req.authenticator_time,
        sequence_number: built_ap_req.sequence_number,
    })
}

/// Build only the HTTP `Authorization` header value for a SPNEGO initiator token.
pub fn authorization_header(
    service_ticket: &TgsRepSession,
    options: InitiatorContextOptions,
) -> Result<String, Error> {
    Ok(init_sec_context(service_ticket, options)?.header)
}

/// Decode an HTTP `Negotiate` header into a SPNEGO token.
///
/// In addition to SPNEGO `NegTokenInit`/`NegTokenResp` values, this accepts
/// raw KRB5 mech tokens and wraps them in the equivalent SPNEGO shape.
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
        .or_else(|spnego_error| raw_krb5_negotiate_token(&bytes, spnego_error))
}

/// Encode a SPNEGO token as an HTTP `Negotiate` header value.
pub fn negotiate_header(token: &SpnegoToken) -> Result<String, Error> {
    Ok(format!(
        "{HTTP_NEGOTIATE} {}",
        base64::engine::general_purpose::STANDARD.encode(token.encode()?)
    ))
}

fn raw_krb5_negotiate_token(bytes: &[u8], spnego_error: Error) -> Result<SpnegoToken, Error> {
    let Ok(krb5) = Krb5MechToken::decode(bytes) else {
        return Err(spnego_error);
    };
    match krb5.token_id {
        Krb5TokenId::ApReq => Ok(SpnegoToken::Init(NegTokenInit::krb5(bytes.to_vec()))),
        Krb5TokenId::ApRep => Ok(SpnegoToken::Resp(
            NegTokenResp::accept_completed().with_response_token(bytes.to_vec()),
        )),
        Krb5TokenId::KrbError => Ok(SpnegoToken::Resp(
            NegTokenResp::reject().with_response_token(bytes.to_vec()),
        )),
    }
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

fn validate_gss_token_id(actual: &[u8], expected: [u8; 2]) -> Result<(), Error> {
    let actual: [u8; 2] = actual.try_into().expect("caller passed exactly two bytes");
    if actual != expected {
        return Err(Error::InvalidGssTokenId { expected, actual });
    }
    Ok(())
}

fn validate_gss_sender(flags: u8, expect_from_acceptor: bool) -> Result<(), Error> {
    let actual_from_acceptor = flags & GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR != 0;
    if actual_from_acceptor != expect_from_acceptor {
        return Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: expect_from_acceptor,
            actual_from_acceptor,
        });
    }
    Ok(())
}

fn wrap_checksum_header(flags: u8, snd_seq_num: u64) -> Vec<u8> {
    wrap_header(flags, 0, 0, snd_seq_num)
}

fn wrap_header(flags: u8, ec: u16, rrc: u16, snd_seq_num: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(GSS_WRAP_HEADER_LEN);
    header.extend_from_slice(&TOK_ID_GSS_WRAP);
    header.push(flags);
    header.push(GSS_WRAP_FILLER);
    header.extend_from_slice(&ec.to_be_bytes());
    header.extend_from_slice(&rrc.to_be_bytes());
    header.extend_from_slice(&snd_seq_num.to_be_bytes());
    header
}

fn rotate_right(bytes: &[u8], count: usize) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let count = count % bytes.len();
    if count == 0 {
        return bytes.to_vec();
    }

    let split = bytes.len() - count;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[split..]);
    out.extend_from_slice(&bytes[..split]);
    out
}

fn rotate_left(bytes: &[u8], count: usize) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let count = count % bytes.len();
    if count == 0 {
        return bytes.to_vec();
    }

    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[count..]);
    out.extend_from_slice(&bytes[..count]);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
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

    /// GSS-API MIC/Wrap token was too short.
    #[error("GSS token too short: expected at least {minimum} bytes, got {actual}")]
    GssTokenTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// GSS-API MIC/Wrap token ID was not the expected value.
    #[error("invalid GSS token ID: expected {expected:02x?}, got {actual:02x?}")]
    InvalidGssTokenId {
        /// Expected two-byte token id.
        expected: [u8; 2],
        /// Actual two-byte token id.
        actual: [u8; 2],
    },

    /// GSS-API token sender direction did not match the caller's expectation.
    #[error(
        "unexpected GSS token sender: expected_from_acceptor={expected_from_acceptor}, actual_from_acceptor={actual_from_acceptor}"
    )]
    UnexpectedGssTokenSender {
        /// Whether caller expected an acceptor token.
        expected_from_acceptor: bool,
        /// Whether token flags identify an acceptor token.
        actual_from_acceptor: bool,
    },

    /// GSS-API token filler bytes were invalid.
    #[error("invalid GSS token filler")]
    InvalidGssFiller,

    /// GSS-API token has no payload for checksum calculation.
    #[error("GSS token payload has not been set")]
    MissingGssPayload,

    /// GSS-API token has no checksum.
    #[error("GSS token checksum has not been set")]
    MissingGssChecksum,

    /// GSS-API token checksum was already set.
    #[error("GSS token checksum has already been set")]
    GssChecksumAlreadySet,

    /// GSS-API sealed token encrypted body was absent.
    #[error("GSS sealed token encrypted body has not been set")]
    MissingGssEncryptedBody,

    /// GSS-API sealed token encrypted body was already set.
    #[error("GSS sealed token encrypted body has already been set")]
    GssEncryptedBodyAlreadySet,

    /// GSS-API token needs encryption instead of a separate checksum.
    #[error("GSS sealed token must be encrypted, not checksummed")]
    SealedGssTokenNeedsEncryption,

    /// GSS-API token was not sealed.
    #[error("GSS token is not sealed")]
    GssTokenNotSealed,

    /// GSS-API token checksum length did not match the header.
    #[error("invalid GSS checksum length: expected {expected} bytes, got {actual}")]
    InvalidGssChecksumLength {
        /// Expected checksum length.
        expected: usize,
        /// Actual checksum length.
        actual: usize,
    },

    /// GSS-API wrap token EC length exceeded remaining bytes.
    #[error(
        "inconsistent wrap checksum length: token has {token_len} bytes, checksum length is {checksum_len}"
    )]
    InconsistentWrapChecksumLength {
        /// Whole token length.
        token_len: usize,
        /// Claimed checksum length.
        checksum_len: usize,
    },

    /// GSS-API checksum verification failed.
    #[error("GSS token checksum mismatch")]
    GssChecksumMismatch,

    /// GSS-API sealed token decrypted to too few bytes.
    #[error("GSS decrypted token too short: expected at least {minimum} bytes, got {actual}")]
    GssDecryptedTokenTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// GSS-API sealed token embedded header did not match the clear header.
    #[error("GSS sealed token embedded header mismatch")]
    InvalidGssEncryptedHeader,

    /// NegTokenInit omitted the mechanism list.
    #[error("NegTokenInit does not contain any mechanism types")]
    MissingMechTypes,

    /// SPNEGO token omitted the mechanism token.
    #[error("SPNEGO token does not contain a mechanism token")]
    MissingMechToken,

    /// SPNEGO token does not carry an AP-REQ.
    #[error("SPNEGO token does not carry a KRB5 AP-REQ")]
    MissingApReq,

    /// SPNEGO token does not carry an AP-REP.
    #[error("SPNEGO token does not carry a KRB5 AP-REP")]
    MissingApRep,

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

    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),

    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
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

    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,

    /// AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    ApRepTimestampMismatch {
        /// Expected AP-REQ authenticator timestamp.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
    },

    /// Service AP-REQ validation failed.
    #[error("service validation error: {0}")]
    Service(#[from] crate::service::Error),

    /// Client AP-REQ construction failed.
    #[error("client AP-REQ construction error: {0}")]
    Client(String),
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

fn integer_to_u32(field: &'static str, value: &rasn::types::Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .map_err(|_| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

fn client_error_to_spnego(error: crate::client::Error) -> Error {
    match error {
        crate::client::Error::Decode { target, message } => Error::Decode { target, message },
        crate::client::Error::Encode { target, message } => Error::Encode { target, message },
        crate::client::Error::InvalidString(source) => {
            Error::InvalidKerberosString(source.to_string())
        }
        crate::client::Error::InvalidKerberosString(message) => {
            Error::InvalidKerberosString(message)
        }
        crate::client::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::client::Error::Crypto(source) => Error::Crypto(source),
        crate::client::Error::Random(source) => Error::Random(source),
        crate::client::Error::TimeOverflow => Error::TimeOverflow,
        other => Error::Client(other.to_string()),
    }
}

fn current_time() -> Result<(SystemTime, u32), Error> {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TimeOverflow)?;
    Ok((
        UNIX_EPOCH + Duration::from_secs(elapsed.as_secs()),
        elapsed.subsec_micros(),
    ))
}

fn random_sequence_number() -> Result<u32, Error> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) & 0x3fff_ffff)
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
