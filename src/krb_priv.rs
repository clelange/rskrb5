//! KRB-PRIV decoding and encrypted-part helpers.

use rasn::types::Integer;

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

/// Kerberos protocol version used by KRB-PRIV.
pub const KRB_PRIV_PVNO: i32 = 5;

/// KRB-PRIV message type.
pub const KRB_PRIV_MSG_TYPE: i32 = 21;

/// Key usage for encrypted KRB-PRIV payloads.
pub const KRB_PRIV_ENCPART_USAGE: u32 = 13;

/// Options for constructing an encrypted KRB-PRIV payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncKrbPrivPartOptions {
    /// Optional sender timestamp.
    pub timestamp: Option<rasn_kerberos::KerberosTime>,
    /// Optional sender timestamp microseconds.
    pub usec: Option<rasn_kerberos::Microseconds>,
    /// Optional sender sequence number.
    pub seq_number: Option<u32>,
    /// Sender host address.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient host address.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl EncKrbPrivPartOptions {
    /// Construct options with the required sender address.
    pub fn new(sender_address: rasn_kerberos::HostAddress) -> Self {
        Self {
            timestamp: None,
            usec: None,
            seq_number: None,
            sender_address,
            recipient_address: None,
        }
    }

    /// Set the sender timestamp and microseconds.
    pub fn with_timestamp(mut self, timestamp: rasn_kerberos::KerberosTime, usec: u32) -> Self {
        self.timestamp = Some(timestamp);
        self.usec = Some(Integer::from(usec));
        self
    }

    /// Set the sender sequence number.
    pub fn with_sequence_number(mut self, seq_number: u32) -> Self {
        self.seq_number = Some(seq_number);
        self
    }

    /// Set the optional recipient address.
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Construct a Kerberos host address.
pub fn host_address(addr_type: i32, address: impl AsRef<[u8]>) -> rasn_kerberos::HostAddress {
    rasn_kerberos::HostAddress {
        addr_type,
        address: address.as_ref().to_vec().into(),
    }
}

/// Construct an IPv4 Kerberos host address.
pub fn ipv4_host_address(octets: [u8; 4]) -> rasn_kerberos::HostAddress {
    host_address(rasn_kerberos::HostAddress::IPV4, octets)
}

/// Construct an IPv6 Kerberos host address.
pub fn ipv6_host_address(octets: [u8; 16]) -> rasn_kerberos::HostAddress {
    host_address(rasn_kerberos::HostAddress::IPV6, octets)
}

/// Build an unencrypted KRB-PRIV part around application data.
pub fn build_enc_krb_priv_part(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
) -> rasn_kerberos::EncKrbPrivPart {
    rasn_kerberos::EncKrbPrivPart {
        user_data: user_data.as_ref().to_vec().into(),
        timestamp: options.timestamp,
        usec: options.usec,
        seq_number: options.seq_number,
        sender_address: options.sender_address,
        recipient_address: options.recipient_address,
    }
}

/// Decode and validate a DER-encoded KRB-PRIV message.
pub fn decode_krb_priv(bytes: &[u8]) -> Result<rasn_kerberos::KrbPriv, Error> {
    let krb_priv = decode::<rasn_kerberos::KrbPriv>("KRB-PRIV", bytes)?;
    validate_krb_priv(&krb_priv)?;
    Ok(krb_priv)
}

/// Validate KRB-PRIV protocol version and message type.
pub fn validate_krb_priv(krb_priv: &rasn_kerberos::KrbPriv) -> Result<(), Error> {
    validate_integer("pvno", &krb_priv.pvno, KRB_PRIV_PVNO)?;
    validate_integer("msg-type", &krb_priv.msg_type, KRB_PRIV_MSG_TYPE)
}

/// Encode a KRB-PRIV message as DER.
pub fn encode_krb_priv(krb_priv: &rasn_kerberos::KrbPriv) -> Result<Vec<u8>, Error> {
    encode("KRB-PRIV", krb_priv)
}

/// Decode a DER-encoded EncKrbPrivPart.
pub fn decode_enc_krb_priv_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    decode("EncKrbPrivPart", bytes)
}

/// Encode an EncKrbPrivPart as DER.
pub fn encode_enc_krb_priv_part(
    enc_part: &rasn_kerberos::EncKrbPrivPart,
) -> Result<Vec<u8>, Error> {
    encode("EncKrbPrivPart", enc_part)
}

/// Build a KRB-PRIV message using a random confounder.
pub fn build_krb_priv(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::KrbPriv, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_krb_priv_with_confounder(user_data, options, key, kvno, &confounder)
}

/// Build a KRB-PRIV message using a caller-supplied confounder.
pub fn build_krb_priv_with_confounder(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbPriv, Error> {
    let enc_part = build_enc_krb_priv_part(user_data, options);
    let plaintext = encode_enc_krb_priv_part(&enc_part)?;
    let encrypted_data = encrypt_krb_priv_enc_part(&plaintext, key, kvno, confounder)?;

    Ok(rasn_kerberos::KrbPriv {
        pvno: Integer::from(KRB_PRIV_PVNO),
        msg_type: Integer::from(KRB_PRIV_MSG_TYPE),
        enc_part: encrypted_data,
    })
}

/// Encrypt an already encoded EncKrbPrivPart with a caller-supplied confounder.
pub fn encrypt_krb_priv_enc_part(
    plaintext: &[u8],
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        plaintext,
        KRB_PRIV_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    })
}

/// Decrypt and decode a KRB-PRIV encrypted part.
pub fn decrypt_krb_priv_enc_part(
    krb_priv: &rasn_kerberos::KrbPriv,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    if krb_priv.enc_part.etype != key.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: krb_priv.enc_part.etype,
        });
    }

    let etype = KerberosEtype::from_etype_id(krb_priv.enc_part.etype)
        .ok_or(Error::UnsupportedEtype(krb_priv.enc_part.etype))?;
    let plaintext = etype.decrypt_message(
        &key.value,
        krb_priv.enc_part.cipher.as_ref(),
        KRB_PRIV_ENCPART_USAGE,
    )?;
    decode_enc_krb_priv_part(crate::der::trim_zero_padded_der(&plaintext))
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

/// KRB-PRIV helper error.
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

    /// A key did not match the encrypted KRB-PRIV data etype.
    #[error(
        "key etype {key_etype} does not match KRB-PRIV encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KRB-PRIV encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
