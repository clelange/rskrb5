//! kadmin protocol data wrappers used by gokrb5 compatibility tests.

use crate::crypto::KerberosEtype;
use crate::keytab::EncryptionKey;
use rasn::prelude::*;

/// Password-change request protocol version (`0xff80`).
pub const CHANGE_PASSWORD_REQUEST_VERSION: u16 = 0xff80;
/// Password-change reply protocol version.
pub const CHANGE_PASSWORD_REPLY_VERSION: u16 = 1;
/// Key usage for encrypted KRB-PRIV payloads.
pub const KRB_PRIV_ENCPART_USAGE: u32 = 13;
/// Password change succeeded.
pub const KPASSWD_SUCCESS: u16 = 0;
/// Request was malformed.
pub const KPASSWD_MALFORMED: u16 = 1;
/// Server hard error.
pub const KPASSWD_HARDERROR: u16 = 2;
/// Authentication error.
pub const KPASSWD_AUTHERROR: u16 = 3;
/// Server soft error.
pub const KPASSWD_SOFTERROR: u16 = 4;
/// Access denied.
pub const KPASSWD_ACCESSDENIED: u16 = 5;
/// Bad protocol version.
pub const KPASSWD_BAD_VERSION: u16 = 6;
/// Initial ticket flag is required.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
const HEADER_LEN: usize = 6;

/// Payload encrypted inside a Kerberos password-change request.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ChangePasswdData {
    /// New password bytes.
    #[rasn(tag(explicit(0)))]
    pub new_passwd: OctetString,
    /// Optional target principal name.
    #[rasn(tag(explicit(1)))]
    pub targ_name: Option<rasn_kerberos::PrincipalName>,
    /// Optional target realm.
    #[rasn(tag(explicit(2)))]
    pub targ_realm: Option<rasn_kerberos::Realm>,
}

/// Password-change request frame containing AP-REQ and KRB-PRIV messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// AP-REQ authenticating the password-change request.
    pub ap_req: rasn_kerberos::ApReq,
    /// KRB-PRIV carrying encrypted `ChangePasswdData`.
    pub krb_priv: rasn_kerberos::KrbPriv,
}

impl Request {
    /// Parse a password-change request frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REQUEST_VERSION {
            return Err(Error::InvalidRequestVersion(frame.version));
        }

        let ap_req_end = usize::from(frame.payload_length);
        if ap_req_end == 0 || ap_req_end >= frame.body.len() {
            return Err(Error::InvalidApReqLength {
                ap_req_length: frame.payload_length,
                body_length: frame.body.len(),
            });
        }

        let ap_req = decode::<rasn_kerberos::ApReq>("AP-REQ", &frame.body[..ap_req_end])?;
        let krb_priv = decode::<rasn_kerberos::KrbPriv>("KRB-PRIV", &frame.body[ap_req_end..])?;
        Ok(Self { ap_req, krb_priv })
    }

    /// Encode a password-change request frame.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let ap_req = encode("AP-REQ", &self.ap_req)?;
        let krb_priv = encode("KRB-PRIV", &self.krb_priv)?;
        if ap_req.len() > usize::from(u16::MAX) {
            return Err(Error::ApReqTooLarge {
                actual: ap_req.len(),
            });
        }

        let message_length = HEADER_LEN + ap_req.len() + krb_priv.len();
        if message_length > usize::from(u16::MAX) {
            return Err(Error::FrameTooLarge {
                actual: message_length,
            });
        }

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&(message_length as u16).to_be_bytes());
        frame.extend_from_slice(&CHANGE_PASSWORD_REQUEST_VERSION.to_be_bytes());
        frame.extend_from_slice(&(ap_req.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ap_req);
        frame.extend_from_slice(&krb_priv);
        Ok(frame)
    }
}

/// Parsed RFC 3244-style password-change reply frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    /// Total message length from the two-byte frame prefix.
    pub message_length: u16,
    /// Protocol version from the reply frame.
    pub version: u16,
    /// DER byte length of the AP-REP section, or zero for a KRB-ERROR reply.
    pub ap_rep_length: u16,
    /// Parsed AP-REP section for successful protocol replies.
    pub ap_rep: Option<rasn_kerberos::ApRep>,
    /// Parsed KRB-PRIV section for successful protocol replies.
    pub krb_priv: Option<rasn_kerberos::KrbPriv>,
    /// Parsed KRB-ERROR section for error replies.
    pub krb_error: Option<rasn_kerberos::KrbError>,
    /// Parsed password-change result from KRB-ERROR `e-data`.
    pub result: Option<ChangePasswordResult>,
}

impl Reply {
    /// Parse a password-change reply frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REPLY_VERSION {
            return Err(Error::InvalidReplyVersion(frame.version));
        }

        if frame.payload_length == 0 {
            let krb_error = decode::<rasn_kerberos::KrbError>("KRB-ERROR", frame.body)?;
            let result = krb_error
                .e_data
                .as_ref()
                .map(|data| ChangePasswordResult::parse(data.as_ref()))
                .transpose()?;
            return Ok(Self {
                message_length: frame.message_length,
                version: frame.version,
                ap_rep_length: frame.payload_length,
                ap_rep: None,
                krb_priv: None,
                krb_error: Some(krb_error),
                result,
            });
        }

        let ap_rep_end = usize::from(frame.payload_length);
        if ap_rep_end >= frame.body.len() {
            return Err(Error::InvalidApRepLength {
                ap_rep_length: frame.payload_length,
                body_length: frame.body.len(),
            });
        }

        let ap_rep = decode::<rasn_kerberos::ApRep>("AP-REP", &frame.body[..ap_rep_end])?;
        let krb_priv = decode::<rasn_kerberos::KrbPriv>("KRB-PRIV", &frame.body[ap_rep_end..])?;

        Ok(Self {
            message_length: frame.message_length,
            version: frame.version,
            ap_rep_length: frame.payload_length,
            ap_rep: Some(ap_rep),
            krb_priv: Some(krb_priv),
            krb_error: None,
            result: None,
        })
    }

    /// Whether the reply carried KRB-ERROR instead of AP-REP/KRB-PRIV.
    pub fn is_krb_error(&self) -> bool {
        self.krb_error.is_some()
    }

    /// Return the password-change result, decrypting KRB-PRIV when needed.
    pub fn decrypt_result(&self, key: &EncryptionKey) -> Result<ChangePasswordResult, Error> {
        if let Some(result) = &self.result {
            return Ok(result.clone());
        }
        if self.krb_error.is_some() {
            return Err(Error::MissingReplyResult);
        }

        let krb_priv = self.krb_priv.as_ref().ok_or(Error::MissingKrbPriv)?;
        if krb_priv.enc_part.etype != key.etype {
            return Err(Error::KeyEtypeMismatch {
                key_etype: key.etype,
                encrypted_data_etype: krb_priv.enc_part.etype,
            });
        }

        let etype = KerberosEtype::from_etype_id(krb_priv.enc_part.etype)
            .ok_or(Error::UnsupportedEtype(krb_priv.enc_part.etype))?;
        let plaintext = etype
            .decrypt_message(
                &key.value,
                krb_priv.enc_part.cipher.as_ref(),
                KRB_PRIV_ENCPART_USAGE,
            )
            .map_err(|source| Error::Crypto {
                message: source.to_string(),
            })?;
        let plaintext = crate::der::trim_zero_padded_der(&plaintext);
        let enc_part = decode::<rasn_kerberos::EncKrbPrivPart>("EncKrbPrivPart", plaintext)?;
        ChangePasswordResult::parse(enc_part.user_data.as_ref())
    }
}

/// Cleartext password-change response code and text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangePasswordResult {
    /// Result code from the first two bytes.
    pub code: u16,
    /// Result text from the remaining bytes.
    pub text: String,
}

impl ChangePasswordResult {
    /// Parse a cleartext password-change response.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::ResponseTooShort {
                actual: bytes.len(),
            });
        }
        Ok(Self {
            code: read_u16(bytes, 0),
            text: String::from_utf8_lossy(&bytes[2..]).into_owned(),
        })
    }

    /// Whether this result indicates a successful password change.
    pub fn is_success(&self) -> bool {
        self.code == KPASSWD_SUCCESS
    }

    /// Return success or an error carrying the kpasswd failure code and text.
    pub fn ensure_success(&self) -> Result<(), Error> {
        if self.is_success() {
            Ok(())
        } else {
            Err(Error::PasswordChangeFailed {
                code: self.code,
                text: self.text.clone(),
            })
        }
    }
}

/// kadmin message parsing errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The frame is too short to contain the kpasswd header.
    #[error("kadmin reply frame is too short: {actual} bytes")]
    FrameTooShort {
        /// Actual byte length.
        actual: usize,
    },
    /// The frame prefix length is smaller than the fixed kpasswd header.
    #[error("invalid kadmin reply message length: {0}")]
    InvalidMessageLength(u16),
    /// The frame prefix length exceeds the supplied byte slice.
    #[error("truncated kadmin reply frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame {
        /// Expected frame byte length.
        expected: usize,
        /// Actual supplied byte length.
        actual: usize,
    },
    /// The reply protocol version is not supported.
    #[error("invalid kadmin reply protocol version: {0}")]
    InvalidReplyVersion(u16),
    /// The request protocol version is not supported.
    #[error("invalid kadmin request protocol version: {0:#06x}")]
    InvalidRequestVersion(u16),
    /// The AP-REQ length points outside the frame body.
    #[error("invalid kadmin AP-REQ length {ap_req_length} for body length {body_length}")]
    InvalidApReqLength {
        /// AP-REQ byte length from the frame header.
        ap_req_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The AP-REP length points outside the frame body.
    #[error("invalid kadmin AP-REP length {ap_rep_length} for body length {body_length}")]
    InvalidApRepLength {
        /// AP-REP byte length from the frame header.
        ap_rep_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The response data is too short to hold a result code.
    #[error("kadmin response data is too short: {actual} bytes")]
    ResponseTooShort {
        /// Actual response byte length.
        actual: usize,
    },
    /// A KRB-ERROR reply did not include kpasswd response data.
    #[error("kadmin reply does not contain response data")]
    MissingReplyResult,
    /// A non-error reply did not include a KRB-PRIV section.
    #[error("kadmin reply does not contain KRB-PRIV")]
    MissingKrbPriv,
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// The supplied key etype did not match the encrypted KRB-PRIV etype.
    #[error(
        "key etype {key_etype} does not match KRB-PRIV encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Supplied key encryption type.
        key_etype: i32,
        /// KRB-PRIV encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Cryptographic decrypt or integrity verification failed.
    #[error("kadmin crypto operation failed: {message}")]
    Crypto {
        /// Crypto error message.
        message: String,
    },
    /// kpasswd returned a non-success result code.
    #[error("kpasswd failed with code {code}: {text}")]
    PasswordChangeFailed {
        /// kpasswd result code.
        code: u16,
        /// kpasswd result text.
        text: String,
    },
    /// DER decoding failed for a framed Kerberos message.
    #[error("{target} decode failed: {message}")]
    Decode {
        /// Kerberos message being decoded.
        target: &'static str,
        /// Decoder error.
        message: String,
    },
    /// DER encoding failed for a framed Kerberos message.
    #[error("{target} encode failed: {message}")]
    Encode {
        /// Kerberos message being encoded.
        target: &'static str,
        /// Encoder error.
        message: String,
    },
    /// Encoded AP-REQ is too large for the two-byte kpasswd length field.
    #[error("encoded AP-REQ is too large: {actual} bytes")]
    ApReqTooLarge {
        /// Encoded AP-REQ byte length.
        actual: usize,
    },
    /// Encoded kadmin frame is too large for the two-byte length prefix.
    #[error("encoded kadmin frame is too large: {actual} bytes")]
    FrameTooLarge {
        /// Encoded frame byte length.
        actual: usize,
    },
}

struct Frame<'a> {
    message_length: u16,
    version: u16,
    payload_length: u16,
    body: &'a [u8],
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

fn parse_header(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::FrameTooShort {
            actual: bytes.len(),
        });
    }

    let message_length = read_u16(bytes, 0);
    let frame_len = usize::from(message_length);
    if frame_len < HEADER_LEN {
        return Err(Error::InvalidMessageLength(message_length));
    }
    if frame_len > bytes.len() {
        return Err(Error::TruncatedFrame {
            expected: frame_len,
            actual: bytes.len(),
        });
    }

    Ok(Frame {
        message_length,
        version: read_u16(bytes, 2),
        payload_length: read_u16(bytes, 4),
        body: &bytes[HEADER_LEN..frame_len],
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
