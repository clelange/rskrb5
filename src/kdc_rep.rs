//! AS-REP/TGS-REP decoding and encrypted-part helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

const KRB5_PVNO: i32 = 5;

/// AS-REP message type.
pub const KRB_AS_REP_MSG_TYPE: i32 = 11;

/// TGS-REP message type.
pub const KRB_TGS_REP_MSG_TYPE: i32 = 13;

/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = 3;

/// Key usage for TGS-REP encrypted parts encrypted with the TGT session key.
pub const TGS_REP_ENCPART_SESSION_KEY_USAGE: u32 = 8;

/// Decode and validate a DER-encoded AS-REP message.
pub fn decode_as_rep(bytes: &[u8]) -> Result<rasn_kerberos::AsRep, Error> {
    let as_rep = decode::<rasn_kerberos::AsRep>("AS-REP", bytes)?;
    validate_as_rep(&as_rep)?;
    Ok(as_rep)
}

/// Validate AS-REP protocol version and message type on an already decoded value.
pub fn validate_as_rep(as_rep: &rasn_kerberos::AsRep) -> Result<(), Error> {
    validate_kdc_rep(&as_rep.0, KRB_AS_REP_MSG_TYPE)
}

/// Encode an AS-REP message as DER.
pub fn encode_as_rep(as_rep: &rasn_kerberos::AsRep) -> Result<Vec<u8>, Error> {
    encode("AS-REP", as_rep)
}

/// Decode and validate a DER-encoded TGS-REP message.
pub fn decode_tgs_rep(bytes: &[u8]) -> Result<rasn_kerberos::TgsRep, Error> {
    let tgs_rep = decode::<rasn_kerberos::TgsRep>("TGS-REP", bytes)?;
    validate_tgs_rep(&tgs_rep)?;
    Ok(tgs_rep)
}

/// Validate TGS-REP protocol version and message type on an already decoded value.
pub fn validate_tgs_rep(tgs_rep: &rasn_kerberos::TgsRep) -> Result<(), Error> {
    validate_kdc_rep(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE)
}

/// Encode a TGS-REP message as DER.
pub fn encode_tgs_rep(tgs_rep: &rasn_kerberos::TgsRep) -> Result<Vec<u8>, Error> {
    encode("TGS-REP", tgs_rep)
}

/// Decode a DER-encoded encrypted KDC reply part.
///
/// RFC 4120 defines separate application tags for AS-REP and TGS-REP
/// encrypted parts, but deployed KDCs sometimes use the TGS tag for both.
/// This accepts either tag, matching gokrb5's `EncKDCRepPart.Unmarshal`.
pub fn decode_enc_kdc_rep_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    match decode::<rasn_kerberos::EncAsRepPart>("EncAsRepPart", bytes) {
        Ok(enc_part) => Ok(enc_part.0),
        Err(as_rep_error) => decode::<rasn_kerberos::EncTgsRepPart>("EncTgsRepPart", bytes)
            .map(|enc_part| enc_part.0)
            .map_err(|_| as_rep_error),
    }
}

/// Encode an encrypted KDC reply part with the AS-REP application tag.
pub fn encode_enc_as_rep_part(enc_part: &rasn_kerberos::EncKdcRepPart) -> Result<Vec<u8>, Error> {
    encode(
        "EncAsRepPart",
        &rasn_kerberos::EncAsRepPart(enc_part.clone()),
    )
}

/// Encode an encrypted KDC reply part with the TGS-REP application tag.
pub fn encode_enc_tgs_rep_part(enc_part: &rasn_kerberos::EncKdcRepPart) -> Result<Vec<u8>, Error> {
    encode(
        "EncTgsRepPart",
        &rasn_kerberos::EncTgsRepPart(enc_part.clone()),
    )
}

/// Decrypt and decode an AS-REP encrypted part.
pub fn decrypt_as_rep_enc_part(
    as_rep: &rasn_kerberos::AsRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    decrypt_kdc_rep_enc_part(&as_rep.0.enc_part, key, AS_REP_ENCPART_USAGE)
}

/// Decrypt and decode a TGS-REP encrypted part.
pub fn decrypt_tgs_rep_enc_part(
    tgs_rep: &rasn_kerberos::TgsRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    decrypt_kdc_rep_enc_part(&tgs_rep.0.enc_part, key, TGS_REP_ENCPART_SESSION_KEY_USAGE)
}

/// Encrypt an AS-REP encrypted part using a random confounder.
pub fn encrypt_as_rep_enc_part(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_as_rep_enc_part_with_confounder(enc_part, key, kvno, &confounder)
}

/// Encrypt an AS-REP encrypted part using an explicit confounder.
pub fn encrypt_as_rep_enc_part_with_confounder(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    encrypt_kdc_rep_enc_part(
        &encode_enc_as_rep_part(enc_part)?,
        key,
        kvno,
        AS_REP_ENCPART_USAGE,
        confounder,
    )
}

/// Encrypt a TGS-REP encrypted part using a random confounder.
pub fn encrypt_tgs_rep_enc_part(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_tgs_rep_enc_part_with_confounder(enc_part, key, kvno, &confounder)
}

/// Encrypt a TGS-REP encrypted part using an explicit confounder.
pub fn encrypt_tgs_rep_enc_part_with_confounder(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    encrypt_kdc_rep_enc_part(
        &encode_enc_tgs_rep_part(enc_part)?,
        key,
        kvno,
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
        confounder,
    )
}

fn validate_kdc_rep(kdc_rep: &rasn_kerberos::KdcRep, msg_type: i32) -> Result<(), Error> {
    validate_integer("pvno", &kdc_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_rep.msg_type, msg_type)?;
    crate::ticket::validate_ticket(&kdc_rep.ticket).map_err(ticket_error)
}

fn decrypt_kdc_rep_enc_part(
    encrypted_data: &rasn_kerberos::EncryptedData,
    key: &EncryptionKey,
    usage: u32,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    if key.etype != encrypted_data.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: encrypted_data.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = etype.decrypt_message(&key.value, encrypted_data.cipher.as_ref(), usage)?;
    decode_enc_kdc_rep_part(crate::der::trim_zero_padded_der(&plaintext))
}

fn encrypt_kdc_rep_enc_part(
    plaintext: &[u8],
    key: &EncryptionKey,
    kvno: Option<u32>,
    usage: u32,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(&key.value, plaintext, usage, confounder)?;
    Ok(rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    })
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

/// KDC reply helper error.
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

    /// A key did not match the encrypted KDC reply data etype.
    #[error(
        "key etype {key_etype} does not match KDC reply encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KDC reply encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
