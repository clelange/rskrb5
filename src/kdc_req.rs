//! AS-REQ/TGS-REQ decoding and request-body helpers.

const KRB5_PVNO: i32 = 5;

/// AS-REQ message type.
pub const KRB_AS_REQ_MSG_TYPE: i32 = 10;

/// TGS-REQ message type.
pub const KRB_TGS_REQ_MSG_TYPE: i32 = 12;

/// Decode and validate a DER-encoded KDC request body.
pub fn decode_kdc_req_body(bytes: &[u8]) -> Result<rasn_kerberos::KdcReqBody, Error> {
    let req_body = decode::<rasn_kerberos::KdcReqBody>("KDC-REQ-BODY", bytes)?;
    validate_kdc_req_body(&req_body)?;
    Ok(req_body)
}

/// Validate nested tickets on an already decoded KDC request body.
pub fn validate_kdc_req_body(req_body: &rasn_kerberos::KdcReqBody) -> Result<(), Error> {
    if let Some(tickets) = &req_body.additional_tickets {
        for ticket in tickets {
            crate::ticket::validate_ticket(ticket).map_err(ticket_error)?;
        }
    }
    Ok(())
}

/// Encode a KDC request body as DER.
pub fn encode_kdc_req_body(req_body: &rasn_kerberos::KdcReqBody) -> Result<Vec<u8>, Error> {
    encode("KDC-REQ-BODY", req_body)
}

/// Decode and validate a DER-encoded AS-REQ message.
pub fn decode_as_req(bytes: &[u8]) -> Result<rasn_kerberos::AsReq, Error> {
    let as_req = decode::<rasn_kerberos::AsReq>("AS-REQ", bytes)?;
    validate_as_req(&as_req)?;
    Ok(as_req)
}

/// Validate AS-REQ protocol version, message type, and nested request body.
pub fn validate_as_req(as_req: &rasn_kerberos::AsReq) -> Result<(), Error> {
    validate_kdc_req(&as_req.0, KRB_AS_REQ_MSG_TYPE)
}

/// Encode an AS-REQ message as DER.
pub fn encode_as_req(as_req: &rasn_kerberos::AsReq) -> Result<Vec<u8>, Error> {
    encode("AS-REQ", as_req)
}

/// Build an AS-REQ message from an already prepared request body and padata.
pub fn build_as_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> rasn_kerberos::AsReq {
    rasn_kerberos::AsReq(rasn_kerberos::KdcReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_AS_REQ_MSG_TYPE),
        padata,
        req_body,
    })
}

/// Encode an AS-REQ message built from an already prepared request body and padata.
pub fn encode_build_as_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> Result<Vec<u8>, Error> {
    encode_as_req(&build_as_req(req_body, padata))
}

/// Decode and validate a DER-encoded TGS-REQ message.
pub fn decode_tgs_req(bytes: &[u8]) -> Result<rasn_kerberos::TgsReq, Error> {
    let tgs_req = decode::<rasn_kerberos::TgsReq>("TGS-REQ", bytes)?;
    validate_tgs_req(&tgs_req)?;
    Ok(tgs_req)
}

/// Validate TGS-REQ protocol version, message type, and nested request body.
pub fn validate_tgs_req(tgs_req: &rasn_kerberos::TgsReq) -> Result<(), Error> {
    validate_kdc_req(&tgs_req.0, KRB_TGS_REQ_MSG_TYPE)
}

/// Encode a TGS-REQ message as DER.
pub fn encode_tgs_req(tgs_req: &rasn_kerberos::TgsReq) -> Result<Vec<u8>, Error> {
    encode("TGS-REQ", tgs_req)
}

/// Build a TGS-REQ message from an already prepared request body and padata.
pub fn build_tgs_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> rasn_kerberos::TgsReq {
    rasn_kerberos::TgsReq(rasn_kerberos::KdcReq {
        pvno: rasn::types::Integer::from(KRB5_PVNO),
        msg_type: rasn::types::Integer::from(KRB_TGS_REQ_MSG_TYPE),
        padata,
        req_body,
    })
}

/// Encode a TGS-REQ message built from an already prepared request body and padata.
pub fn encode_build_tgs_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> Result<Vec<u8>, Error> {
    encode_tgs_req(&build_tgs_req(req_body, padata))
}

fn validate_kdc_req(kdc_req: &rasn_kerberos::KdcReq, msg_type: i32) -> Result<(), Error> {
    validate_integer("pvno", &kdc_req.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_req.msg_type, msg_type)?;
    validate_kdc_req_body(&kdc_req.req_body)
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

/// KDC request helper error.
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
