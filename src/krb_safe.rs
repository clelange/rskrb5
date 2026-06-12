//! KRB-SAFE decoding and checksum helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

const KRB5_PVNO: i32 = 5;

/// KRB-SAFE message type.
pub const KRB_SAFE_MSG_TYPE: i32 = 20;

/// Key usage for KRB-SAFE checksums.
pub const KRB_SAFE_CHECKSUM_USAGE: u32 = 15;

/// Decode and validate a DER-encoded KRB-SAFE message.
pub fn decode_krb_safe(bytes: &[u8]) -> Result<rasn_kerberos::KrbSafe, Error> {
    let krb_safe = decode::<rasn_kerberos::KrbSafe>("KRB-SAFE", bytes)?;
    validate_integer("pvno", &krb_safe.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_safe.msg_type, KRB_SAFE_MSG_TYPE)?;
    Ok(krb_safe)
}

/// Encode a KRB-SAFE message as DER.
pub fn encode_krb_safe(krb_safe: &rasn_kerberos::KrbSafe) -> Result<Vec<u8>, Error> {
    encode("KRB-SAFE", krb_safe)
}

/// Build a KRB-SAFE message with a keyed checksum over the safe body.
pub fn build_krb_safe(
    body: rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbSafe, Error> {
    let cksum = krb_safe_checksum(&body, key)?;
    Ok(rasn_kerberos::KrbSafe {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_SAFE_MSG_TYPE),
        body,
        cksum,
    })
}

/// Compute the keyed checksum for a KRB-SAFE body.
pub fn krb_safe_checksum(
    body: &rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::Checksum, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let body_der = encode("KrbSafeBody", body)?;
    Ok(rasn_kerberos::Checksum {
        r#type: etype.checksum_type_id(),
        checksum: etype
            .checksum(&key.value, &body_der, KRB_SAFE_CHECKSUM_USAGE)?
            .into(),
    })
}

/// Verify the keyed checksum in a KRB-SAFE message.
pub fn verify_krb_safe_checksum(
    krb_safe: &rasn_kerberos::KrbSafe,
    key: &EncryptionKey,
) -> Result<(), Error> {
    let etype = KerberosEtype::from_checksum_type_id(krb_safe.cksum.r#type)
        .ok_or(Error::UnsupportedChecksumType(krb_safe.cksum.r#type))?;
    if etype.etype_id() != key.etype {
        return Err(Error::KeyChecksumTypeMismatch {
            key_etype: key.etype,
            checksum_type: krb_safe.cksum.r#type,
        });
    }
    let body_der = encode("KrbSafeBody", &krb_safe.body)?;
    if !etype.verify_checksum(
        &key.value,
        &body_der,
        krb_safe.cksum.checksum.as_ref(),
        KRB_SAFE_CHECKSUM_USAGE,
    ) {
        return Err(Error::ChecksumMismatch);
    }
    Ok(())
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

/// KRB-SAFE helper error.
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

    /// The encryption type is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),

    /// The checksum type is not implemented yet.
    #[error("unsupported checksum type: {0}")]
    UnsupportedChecksumType(i32),

    /// A key did not match the KRB-SAFE checksum type.
    #[error("key etype {key_etype} does not match KRB-SAFE checksum type {checksum_type}")]
    KeyChecksumTypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// KRB-SAFE checksum type.
        checksum_type: i32,
    },

    /// KRB-SAFE checksum verification failed.
    #[error("KRB-SAFE checksum verification failed")]
    ChecksumMismatch,

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
