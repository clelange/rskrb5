//! KRB-CRED decoding and encrypted-part helpers.

use std::str;

use crate::ccache;
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

/// Convert decrypted KRB-CRED contents into ccache credentials.
pub fn decrypted_krb_cred_to_ccache_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    enc_part: &rasn_kerberos::EncKrbCredPart,
) -> Result<Vec<ccache::Credential>, Error> {
    if krb_cred.tickets.len() != enc_part.ticket_info.len() {
        return Err(Error::TicketInfoCountMismatch {
            ticket_count: krb_cred.tickets.len(),
            info_count: enc_part.ticket_info.len(),
        });
    }

    krb_cred
        .tickets
        .iter()
        .zip(enc_part.ticket_info.iter())
        .map(|(ticket, info)| krb_cred_info_to_ccache_credential(ticket, info))
        .collect()
}

fn krb_cred_info_to_ccache_credential(
    ticket: &rasn_kerberos::Ticket,
    info: &rasn_kerberos::KrbCredInfo,
) -> Result<ccache::Credential, Error> {
    let client = required_principal(
        "KrbCredInfo.pname",
        info.prealm.as_ref(),
        info.pname.as_ref(),
    )?;
    let server = match optional_principal(info.srealm.as_ref(), info.sname.as_ref())? {
        Some(server) => server,
        None => principal_from_parts(&ticket.realm, &ticket.sname)?,
    };
    Ok(ccache::Credential {
        client,
        server,
        key: ccache::EncryptionKey {
            etype: info.key.r#type,
            value: info.key.value.as_ref().to_vec(),
        },
        times: ccache::CredentialTimes {
            auth_time: optional_kerberos_time_to_u32(info.auth_time.as_ref())?,
            start_time: optional_kerberos_time_to_u32(
                info.start_time.as_ref().or(info.auth_time.as_ref()),
            )?,
            end_time: optional_kerberos_time_to_u32(info.end_time.as_ref())?,
            renew_till: optional_kerberos_time_to_u32(info.renew_till.as_ref())?,
        },
        is_skey: false,
        ticket_flags: info
            .flags
            .as_ref()
            .map(ticket_flags_to_bytes)
            .unwrap_or_default(),
        addresses: info
            .caddr
            .as_ref()
            .map(|addresses| {
                addresses
                    .iter()
                    .map(|address| ccache::HostAddress {
                        addr_type: address.addr_type,
                        address: address.address.as_ref().to_vec(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        auth_data: Vec::new(),
        ticket: encode("Ticket", ticket)?,
        second_ticket: Vec::new(),
    })
}

fn required_principal(
    field: &'static str,
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<ccache::Principal, Error> {
    match (realm, name) {
        (Some(realm), Some(name)) => principal_from_parts(realm, name),
        _ => Err(Error::MissingKrbCredInfoField(field)),
    }
}

fn optional_principal(
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<Option<ccache::Principal>, Error> {
    match (realm, name) {
        (Some(realm), Some(name)) => principal_from_parts(realm, name).map(Some),
        (None, None) => Ok(None),
        _ => Err(Error::MissingKrbCredInfoField("KrbCredInfo.srealm/sname")),
    }
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<ccache::Principal, Error> {
    Ok(ccache::Principal::new(
        kerberos_string_to_string(realm)?,
        name.r#type,
        name.string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

fn optional_kerberos_time_to_u32(time: Option<&rasn_kerberos::KerberosTime>) -> Result<u32, Error> {
    time.map(kerberos_time_to_u32)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn kerberos_time_to_u32(time: &rasn_kerberos::KerberosTime) -> Result<u32, Error> {
    u32::try_from(time.0.timestamp()).map_err(|_| Error::TimeOutOfRange)
}

fn ticket_flags_to_bytes(flags: &rasn_kerberos::TicketFlags) -> [u8; 4] {
    let raw = flags.0.as_raw_slice();
    [
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ]
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

    /// The KRB-CRED ticket count and ticket-info count differed.
    #[error("KRB-CRED has {ticket_count} tickets but {info_count} ticket-info entries")]
    TicketInfoCountMismatch {
        /// Ticket count.
        ticket_count: usize,
        /// Ticket-info count.
        info_count: usize,
    },

    /// A field required for ccache conversion was absent.
    #[error("KRB-CRED missing required field {0}")]
    MissingKrbCredInfoField(&'static str),

    /// A Kerberos time could not fit in a ccache timestamp.
    #[error("Kerberos time cannot be represented as a ccache timestamp")]
    TimeOutOfRange,

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
}
