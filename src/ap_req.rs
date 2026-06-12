//! AP-REQ decoding and authenticator helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

const KRB5_PVNO: i32 = 5;

/// AP-REQ message type.
pub const KRB_AP_REQ_MSG_TYPE: i32 = 14;

/// Key usage for TGS-REQ AP-REQ authenticators.
pub const TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE: u32 = 7;

/// Key usage for normal AP-REQ authenticators.
pub const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;

/// Decode and validate a DER-encoded AP-REQ message.
pub fn decode_ap_req(bytes: &[u8]) -> Result<rasn_kerberos::ApReq, Error> {
    let ap_req = decode::<rasn_kerberos::ApReq>("AP-REQ", bytes)?;
    validate_ap_req(&ap_req)?;
    Ok(ap_req)
}

/// Validate AP-REQ protocol version and message type on an already decoded value.
pub fn validate_ap_req(ap_req: &rasn_kerberos::ApReq) -> Result<(), Error> {
    validate_integer("pvno", &ap_req.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &ap_req.msg_type, KRB_AP_REQ_MSG_TYPE)
}

/// Encode an AP-REQ message as DER.
pub fn encode_ap_req(ap_req: &rasn_kerberos::ApReq) -> Result<Vec<u8>, Error> {
    encode("AP-REQ", ap_req)
}

/// Decode a DER-encoded Authenticator.
pub fn decode_authenticator(bytes: &[u8]) -> Result<rasn_kerberos::Authenticator, Error> {
    decode::<rasn_kerberos::Authenticator>("Authenticator", bytes)
}

/// Encode an Authenticator as DER.
pub fn encode_authenticator(
    authenticator: &rasn_kerberos::Authenticator,
) -> Result<Vec<u8>, Error> {
    encode("Authenticator", authenticator)
}

/// Decrypt and decode an AP-REQ authenticator with an explicit key usage.
pub fn decrypt_ap_req_authenticator(
    ap_req: &rasn_kerberos::ApReq,
    key: &EncryptionKey,
    usage: u32,
) -> Result<rasn_kerberos::Authenticator, Error> {
    if key.etype != ap_req.authenticator.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: ap_req.authenticator.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext =
        etype.decrypt_message(&key.value, ap_req.authenticator.cipher.as_ref(), usage)?;
    decode_authenticator(crate::der::trim_zero_padded_der(&plaintext))
}

/// Return the AP-REQ authenticator key usage implied by the ticket service.
pub fn authenticator_usage_for_ticket(ticket: &rasn_kerberos::Ticket) -> u32 {
    if ticket
        .sname
        .string
        .first()
        .is_some_and(|component| component.as_bytes() == b"krbtgt")
    {
        TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE
    } else {
        AP_REQ_AUTHENTICATOR_USAGE
    }
}

/// Convert a raw AP option bit mask into Kerberos AP options.
pub fn ap_options_from_bits(bits: u32) -> rasn_kerberos::ApOptions {
    rasn_kerberos::ApOptions(rasn_kerberos::KerberosFlags::from_slice(
        &bits.to_be_bytes(),
    ))
}

/// Convert Kerberos AP options into a raw 32-bit mask.
pub fn ap_options_to_bits(ap_options: &rasn_kerberos::ApOptions) -> u32 {
    let raw = ap_options.0.as_raw_slice();
    u32::from_be_bytes([
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ])
}

/// Build an AP-REQ message using a random confounder.
pub fn build_ap_req(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::ApReq, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_ap_req_with_confounder(
        ticket,
        ap_options,
        authenticator,
        key,
        usage,
        kvno,
        &confounder,
    )
}

/// Build an AP-REQ message using an explicit confounder.
pub fn build_ap_req_with_confounder(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::ApReq, Error> {
    let plaintext = encode_authenticator(authenticator)?;
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher =
        etype.encrypt_message_with_confounder(&key.value, &plaintext, usage, confounder)?;
    Ok(rasn_kerberos::ApReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AP_REQ_MSG_TYPE),
        ap_options,
        ticket,
        authenticator: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode an AP-REQ message built using a random confounder.
pub fn encode_build_ap_req(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ap_req = build_ap_req(ticket, ap_options, authenticator, key, usage, kvno)?;
    encode_ap_req(&ap_req)
}

/// Encode an AP-REQ message built using an explicit confounder.
pub fn encode_build_ap_req_with_confounder(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ap_req = build_ap_req_with_confounder(
        ticket,
        ap_options,
        authenticator,
        key,
        usage,
        kvno,
        confounder,
    )?;
    encode_ap_req(&ap_req)
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

/// AP-REQ helper error.
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

    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
