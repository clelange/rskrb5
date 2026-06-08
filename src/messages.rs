//! Kerberos message/type wrappers that need gokrb5-compatible DER behavior.

use rasn::prelude::*;

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

/// Errors from `EncryptedData` conversion helpers.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The ASN.1 INTEGER `kvno` cannot be represented as the requested type.
    #[error("encrypted data kvno cannot be represented as {target}: {kvno:?}")]
    KvnoOutOfRange {
        /// Target integer representation.
        target: &'static str,
        /// Original ASN.1 INTEGER value.
        kvno: Integer,
    },
}
