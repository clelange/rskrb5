//! Kerberos message/type wrappers that need gokrb5-compatible DER behavior.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rasn::prelude::*;

const KRB5_PVNO: i32 = 5;
const KRB_ERROR_MSG_TYPE: i32 = 30;

/// RFC 4120 `EncryptedData` with a signed/raw ASN.1 `kvno`.
///
/// `rasn_kerberos::EncryptedData` models `kvno` as `u32`, which is appropriate
/// for normal Kerberos messages but normalizes gokrb5's signed edge-case
/// fixtures on re-encode. This wrapper preserves those DER fixtures exactly.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct EncryptedData {
    /// Identifies the encryption algorithm used to encipher `cipher`.
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    /// Key version number, kept as ASN.1 INTEGER for gokrb5 signed edge cases.
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<Integer>,
    /// Enciphered text.
    #[rasn(tag(explicit(2)))]
    pub cipher: OctetString,
}

/// MS-SFU `PA-FOR-USER` padata value used by S4U2Self.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct PaForUser {
    /// User principal name.
    #[rasn(tag(explicit(0)))]
    pub user_name: rasn_kerberos::PrincipalName,
    /// User realm.
    #[rasn(tag(explicit(1)))]
    pub user_realm: rasn_kerberos::Realm,
    /// Checksum over the MS-SFU S4U byte array.
    #[rasn(tag(explicit(2)))]
    pub cksum: rasn_kerberos::Checksum,
    /// Authentication package name, normally `Kerberos`.
    #[rasn(tag(explicit(3)))]
    pub auth_package: rasn_kerberos::KerberosString,
}

impl PaForUser {
    /// Decode a DER-encoded `PA-FOR-USER` value.
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_der("PA-FOR-USER", bytes)
    }

    /// Encode the value as DER.
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-FOR-USER", self)
    }
}

impl EncryptedData {
    /// Build the preserving wrapper from the upstream rasn Kerberos type.
    pub fn from_rasn(value: rasn_kerberos::EncryptedData) -> Self {
        Self {
            etype: value.etype,
            kvno: value.kvno.map(Integer::from),
            cipher: value.cipher,
        }
    }

    /// Convert to the upstream rasn Kerberos type when `kvno` is a valid `u32`.
    pub fn try_to_rasn(&self) -> Result<rasn_kerberos::EncryptedData, Error> {
        Ok(rasn_kerberos::EncryptedData {
            etype: self.etype,
            kvno: self.kvno_u32()?,
            cipher: self.cipher.clone(),
        })
    }

    /// Return `kvno` as a signed 32-bit value, matching gokrb5's `int` tests.
    pub fn kvno_i32(&self) -> Result<Option<i32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                i32::try_from(kvno).map_err(|_| Error::KvnoOutOfRange {
                    target: "i32",
                    kvno: kvno.clone(),
                })
            })
            .transpose()
    }

    /// Return `kvno` as the normal non-negative Kerberos `u32` representation.
    pub fn kvno_u32(&self) -> Result<Option<u32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                u32::try_from(kvno).map_err(|_| Error::KvnoOutOfRange {
                    target: "u32",
                    kvno: kvno.clone(),
                })
            })
            .transpose()
    }
}

/// Principal summary decoded from a Kerberos message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalNameInfo {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl PrincipalNameInfo {
    /// Principal components joined with `/`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Decoded KRB-ERROR fields useful for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KrbErrorInfo {
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
    /// Client principal carried by the error, when present.
    pub client: Option<PrincipalNameInfo>,
    /// Service principal that issued the error.
    pub service: PrincipalNameInfo,
    /// Optional human-readable error text.
    pub e_text: Option<String>,
    /// Raw e-data bytes, when present.
    pub e_data: Option<Vec<u8>>,
}

impl KrbErrorInfo {
    /// Decode and validate a DER-encoded KRB-ERROR.
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_rasn(&decode_der("KRB-ERROR", bytes)?)
    }

    /// Build a diagnostic summary from a decoded KRB-ERROR.
    pub fn from_rasn(error: &rasn_kerberos::KrbError) -> Result<Self, Error> {
        validate_integer("pvno", &error.pvno, KRB5_PVNO)?;
        validate_integer("msg-type", &error.msg_type, KRB_ERROR_MSG_TYPE)?;
        let client = match (&error.crealm, &error.cname) {
            (Some(realm), Some(name)) => Some(principal_from_parts(realm, name)?),
            _ => None,
        };
        Ok(Self {
            ctime: error
                .ctime
                .as_ref()
                .map(system_time_from_kerberos_time)
                .transpose()?,
            cusec: error
                .cusec
                .as_ref()
                .map(|value| integer_to_u32("cusec", value))
                .transpose()?,
            stime: system_time_from_kerberos_time(&error.stime)?,
            susec: integer_to_u32("susec", &error.susec)?,
            error_code: error.error_code,
            client,
            service: principal_from_parts(&error.realm, &error.sname)?,
            e_text: error
                .e_text
                .as_ref()
                .map(kerberos_string_to_string)
                .transpose()?,
            e_data: error.e_data.as_ref().map(|data| data.as_ref().to_vec()),
        })
    }
}

/// Decode a DER value with a typed error.
pub fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    rasn::der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode a value to DER with a typed error.
pub fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    rasn::der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Errors from Kerberos message helpers.
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
    InvalidString(#[from] std::str::Utf8Error),

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
    u32::try_from(value).map_err(|_| Error::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<PrincipalNameInfo, Error> {
    Ok(PrincipalNameInfo {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(std::str::from_utf8(value.as_bytes())?.to_owned())
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
