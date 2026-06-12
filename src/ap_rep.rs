//! AP-REP decoding and encrypted-part helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

const KRB5_PVNO: i32 = 5;

/// AP-REP message type.
pub const KRB_AP_REP_MSG_TYPE: i32 = 15;

/// Key usage for AP-REP encrypted parts.
pub const AP_REP_ENCPART_USAGE: u32 = 12;

/// Decode and validate a DER-encoded AP-REP message.
pub fn decode_ap_rep(bytes: &[u8]) -> Result<rasn_kerberos::ApRep, Error> {
    let ap_rep = decode::<rasn_kerberos::ApRep>("AP-REP", bytes)?;
    validate_ap_rep(&ap_rep)?;
    Ok(ap_rep)
}

/// Validate AP-REP protocol version and message type on an already decoded value.
pub fn validate_ap_rep(ap_rep: &rasn_kerberos::ApRep) -> Result<(), Error> {
    validate_integer("pvno", &ap_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &ap_rep.msg_type, KRB_AP_REP_MSG_TYPE)
}

/// Encode an AP-REP message as DER.
pub fn encode_ap_rep(ap_rep: &rasn_kerberos::ApRep) -> Result<Vec<u8>, Error> {
    encode("AP-REP", ap_rep)
}

/// Decode a DER-encoded EncAPRepPart.
pub fn decode_enc_ap_rep_part(bytes: &[u8]) -> Result<rasn_kerberos::EncApRepPart, Error> {
    decode::<rasn_kerberos::EncApRepPart>("EncApRepPart", bytes)
}

/// Decrypt and decode an AP-REP encrypted part.
pub fn decrypt_ap_rep_enc_part(
    ap_rep: &rasn_kerberos::ApRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncApRepPart, Error> {
    if key.etype != ap_rep.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: ap_rep.enc_part.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = etype.decrypt_message(
        &key.value,
        ap_rep.enc_part.cipher.as_ref(),
        AP_REP_ENCPART_USAGE,
    )?;
    decode_enc_ap_rep_part(&plaintext)
}

/// Build an AP-REP message using a random confounder.
pub fn build_ap_rep(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::ApRep, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_ap_rep_with_confounder(enc_part, key, kvno, &confounder)
}

/// Build an AP-REP message using an explicit confounder.
pub fn build_ap_rep_with_confounder(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::ApRep, Error> {
    let plaintext = encode("EncApRepPart", enc_part)?;
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        AP_REP_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::ApRep {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AP_REP_MSG_TYPE),
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode an AP-REP message built using a random confounder.
pub fn encode_build_ap_rep(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ap_rep = build_ap_rep(enc_part, key, kvno)?;
    encode_ap_rep(&ap_rep)
}

/// Encode an AP-REP message built using an explicit confounder.
pub fn encode_build_ap_rep_with_confounder(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ap_rep = build_ap_rep_with_confounder(enc_part, key, kvno, confounder)?;
    encode_ap_rep(&ap_rep)
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

/// AP-REP helper error.
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

    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
