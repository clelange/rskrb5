//! Ticket decoding and encrypted-part helpers.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;

/// Kerberos ticket version.
pub const KRB5_TKT_VNO: i32 = 5;

/// Key usage for ticket encrypted parts.
pub const KDC_REP_TICKET_USAGE: u32 = 2;

/// Decode and validate a DER-encoded Ticket.
pub fn decode_ticket(bytes: &[u8]) -> Result<rasn_kerberos::Ticket, Error> {
    let ticket = decode::<rasn_kerberos::Ticket>("Ticket", bytes)?;
    validate_ticket(&ticket)?;
    Ok(ticket)
}

/// Validate the ticket version on an already decoded value.
pub fn validate_ticket(ticket: &rasn_kerberos::Ticket) -> Result<(), Error> {
    validate_integer("tkt-vno", &ticket.tkt_vno, KRB5_TKT_VNO)
}

/// Encode a Ticket as DER.
pub fn encode_ticket(ticket: &rasn_kerberos::Ticket) -> Result<Vec<u8>, Error> {
    encode("Ticket", ticket)
}

/// Decode a DER-encoded EncTicketPart.
pub fn decode_enc_ticket_part(bytes: &[u8]) -> Result<rasn_kerberos::EncTicketPart, Error> {
    decode::<rasn_kerberos::EncTicketPart>("EncTicketPart", bytes)
}

/// Decrypt and decode a ticket encrypted part.
pub fn decrypt_ticket_enc_part(
    ticket: &rasn_kerberos::Ticket,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncTicketPart, Error> {
    if key.etype != ticket.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: ticket.enc_part.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = etype.decrypt_message(
        &key.value,
        ticket.enc_part.cipher.as_ref(),
        KDC_REP_TICKET_USAGE,
    )?;
    decode_enc_ticket_part(crate::der::trim_zero_padded_der(&plaintext))
}

/// Build a Ticket using a random confounder.
pub fn build_ticket(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::Ticket, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_ticket_with_confounder(realm, sname, enc_part, key, kvno, &confounder)
}

/// Build a Ticket using an explicit confounder.
pub fn build_ticket_with_confounder(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::Ticket, Error> {
    let plaintext = encode("EncTicketPart", enc_part)?;
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        KDC_REP_TICKET_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::Ticket {
        tkt_vno: rasn::types::Integer::from(KRB5_TKT_VNO),
        realm,
        sname,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode a Ticket built using a random confounder.
pub fn encode_build_ticket(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ticket = build_ticket(realm, sname, enc_part, key, kvno)?;
    encode_ticket(&ticket)
}

/// Encode a Ticket built using an explicit confounder.
pub fn encode_build_ticket_with_confounder(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ticket = build_ticket_with_confounder(realm, sname, enc_part, key, kvno, confounder)?;
    encode_ticket(&ticket)
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

/// Ticket helper error.
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

    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
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
