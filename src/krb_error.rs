//! KRB-ERROR decoding and METHOD-DATA helpers.

use rasn::types::Integer;

pub use crate::messages::{KrbErrorInfo, PrincipalNameInfo};

/// Kerberos protocol version.
pub const KRB5_PVNO: i32 = 5;

/// KRB-ERROR message type.
pub const KRB_ERROR_MSG_TYPE: i32 = 30;

/// Decode and validate a DER-encoded KRB-ERROR message.
pub fn decode_krb_error(bytes: &[u8]) -> Result<rasn_kerberos::KrbError, Error> {
    let krb_error = decode::<rasn_kerberos::KrbError>("KRB-ERROR", bytes)?;
    validate_krb_error(&krb_error)?;
    Ok(krb_error)
}

/// Validate KRB-ERROR protocol version, message type, and diagnostic fields.
pub fn validate_krb_error(krb_error: &rasn_kerberos::KrbError) -> Result<(), Error> {
    krb_error_info(krb_error).map(|_| ())
}

/// Encode a KRB-ERROR message as DER.
pub fn encode_krb_error(krb_error: &rasn_kerberos::KrbError) -> Result<Vec<u8>, Error> {
    encode("KRB-ERROR", krb_error)
}

/// Decode a DER-encoded KRB-ERROR directly into diagnostic fields.
pub fn decode_krb_error_info(bytes: &[u8]) -> Result<KrbErrorInfo, Error> {
    let krb_error = decode_krb_error(bytes)?;
    krb_error_info(&krb_error)
}

/// Build diagnostic fields from a decoded KRB-ERROR.
pub fn krb_error_info(krb_error: &rasn_kerberos::KrbError) -> Result<KrbErrorInfo, Error> {
    KrbErrorInfo::from_rasn(krb_error).map_err(message_error)
}

/// Decode DER-encoded METHOD-DATA from a KRB-ERROR `e-data` value.
pub fn decode_method_data(bytes: &[u8]) -> Result<rasn_kerberos::MethodData, Error> {
    decode::<rasn_kerberos::MethodData>("METHOD-DATA", bytes)
}

/// Encode METHOD-DATA as DER for use in KRB-ERROR `e-data`.
pub fn encode_method_data(method_data: &rasn_kerberos::MethodData) -> Result<Vec<u8>, Error> {
    encode("METHOD-DATA", method_data)
}

/// Decode preauthentication METHOD-DATA when the KRB-ERROR has the supplied code.
///
/// RFC 4120 uses `KDC_ERR_PREAUTH_REQUIRED` for this path. The code is supplied
/// by the caller so this module stays independent from the higher-level client
/// constants.
pub fn preauth_method_data(
    krb_error: &rasn_kerberos::KrbError,
    preauth_required_error_code: i32,
) -> Result<rasn_kerberos::MethodData, Error> {
    let info = krb_error_info(krb_error)?;
    if info.error_code != preauth_required_error_code {
        return Ok(Vec::new());
    }
    info.e_data
        .as_deref()
        .map(decode_method_data)
        .transpose()
        .map(Option::unwrap_or_default)
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

fn message_error(error: crate::messages::Error) -> Error {
    match error {
        crate::messages::Error::Decode { target, message } => Error::Decode { target, message },
        crate::messages::Error::Encode { target, message } => Error::Encode { target, message },
        crate::messages::Error::InvalidString(source) => Error::InvalidString(source.to_string()),
        crate::messages::Error::IntegerOutOfRange { field, value } => {
            Error::IntegerOutOfRange { field, value }
        }
        crate::messages::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::messages::Error::KvnoOutOfRange { target, kvno } => {
            Error::KvnoOutOfRange { target, kvno }
        }
        crate::messages::Error::TimeOverflow => Error::TimeOverflow,
    }
}

/// KRB-ERROR helper error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
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
    InvalidString(String),

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

    /// The ASN.1 INTEGER `kvno` cannot be represented as the requested type.
    #[error("encrypted data kvno cannot be represented as {target}: {kvno:?}")]
    KvnoOutOfRange {
        /// Target integer representation.
        target: &'static str,
        /// Original ASN.1 INTEGER value.
        kvno: Integer,
    },

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}
