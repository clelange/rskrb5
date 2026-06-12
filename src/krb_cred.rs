//! KRB-CRED decoding and encrypted-part helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

const KRB5_PVNO: i32 = 5;

/// KRB-CRED message type.
pub const KRB_CRED_MSG_TYPE: i32 = 22;

/// Key usage for KRB-CRED encrypted parts.
pub const KRB_CRED_ENCPART_USAGE: u32 = 14;

/// Decode and validate a DER-encoded KRB-CRED message.
pub fn decode_krb_cred(bytes: &[u8]) -> Result<rasn_kerberos::KrbCred, Error> {
    let krb_cred = decode::<rasn_kerberos::KrbCred>("KRB-CRED", bytes)?;
    validate_integer("pvno", &krb_cred.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_cred.msg_type, KRB_CRED_MSG_TYPE)?;
    Ok(krb_cred)
}

/// Decode a DER-encoded EncKrbCredPart.
pub fn decode_enc_krb_cred_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    decode::<rasn_kerberos::EncKrbCredPart>("EncKrbCredPart", bytes)
}

/// Decrypt and decode a KRB-CRED encrypted part.
pub fn decrypt_krb_cred_enc_part(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    if key.etype != krb_cred.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: krb_cred.enc_part.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = etype.decrypt_message(
        &key.value,
        krb_cred.enc_part.cipher.as_ref(),
        KRB_CRED_ENCPART_USAGE,
    )?;
    decode_enc_krb_cred_part(&plaintext)
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

/// KRB-CRED helper error.
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

    /// A key did not match the encrypted KRB-CRED data etype.
    #[error(
        "key etype {key_etype} does not match KRB-CRED encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KRB-CRED encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
