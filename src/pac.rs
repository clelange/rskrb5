//! Microsoft Privilege Attribute Certificate (PAC) parsing.
//!
//! This module covers the PAC surface that gokrb5 consumes on the service
//! path: the PAC container, KERB_VALIDATION_INFO, client information,
//! UPN/DNS information, PAC signatures, and AES server checksum verification.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{self, KerberosEtype};
use crate::keytab::EncryptionKey;

/// `AD-IF-RELEVANT` authorization-data type.
pub const AD_IF_RELEVANT: i32 = 1;
/// Microsoft `AD-WIN2K-PAC` authorization-data type.
pub const AD_WIN2K_PAC: i32 = 128;

/// `KERB_VALIDATION_INFO` PAC buffer type.
pub const INFO_TYPE_KERB_VALIDATION_INFO: u32 = 1;
/// PAC credentials buffer type.
pub const INFO_TYPE_CREDENTIALS: u32 = 2;
/// PAC server checksum buffer type.
pub const INFO_TYPE_PAC_SERVER_SIGNATURE_DATA: u32 = 6;
/// PAC KDC checksum buffer type.
pub const INFO_TYPE_PAC_KDC_SIGNATURE_DATA: u32 = 7;
/// PAC client info buffer type.
pub const INFO_TYPE_PAC_CLIENT_INFO: u32 = 10;
/// PAC S4U delegation info buffer type.
pub const INFO_TYPE_S4U_DELEGATION_INFO: u32 = 11;
/// PAC UPN/DNS info buffer type.
pub const INFO_TYPE_UPN_DNS_INFO: u32 = 12;
/// PAC client claims info buffer type.
pub const INFO_TYPE_PAC_CLIENT_CLAIMS_INFO: u32 = 13;
/// PAC device info buffer type.
pub const INFO_TYPE_PAC_DEVICE_INFO: u32 = 14;
/// PAC device claims info buffer type.
pub const INFO_TYPE_PAC_DEVICE_CLAIMS_INFO: u32 = 15;

/// Microsoft unsigned HMAC-MD5 PAC checksum type.
pub const CHECKSUM_HMAC_MD5_UNSIGNED: u32 = 0xffff_ff76;
/// Kerberos AES128 HMAC-SHA1-96 checksum type.
pub const CHECKSUM_HMAC_SHA1_96_AES128: u32 = 15;
/// Kerberos AES256 HMAC-SHA1-96 checksum type.
pub const CHECKSUM_HMAC_SHA1_96_AES256: u32 = 16;
/// Kerberos AES128 SHA2 checksum type.
pub const CHECKSUM_HMAC_SHA256_128_AES128: u32 = 19;
/// Kerberos AES256 SHA2 checksum type.
pub const CHECKSUM_HMAC_SHA384_192_AES256: u32 = 20;

/// Claims data is not compressed.
pub const CLAIMS_COMPRESSION_FORMAT_NONE: u16 = 0;
/// Claims data uses LZNT1 compression.
pub const CLAIMS_COMPRESSION_FORMAT_LZNT1: u16 = 2;
/// Claims data uses XPRESS compression.
pub const CLAIMS_COMPRESSION_FORMAT_XPRESS: u16 = 3;
/// Claims data uses XPRESS Huffman compression.
pub const CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 4;

/// Claims originated in Active Directory.
pub const CLAIMS_SOURCE_TYPE_AD: u16 = 1;

/// Signed 64-bit integer claim value type.
pub const CLAIM_TYPE_ID_INT64: u16 = 1;
/// Unsigned 64-bit integer claim value type.
pub const CLAIM_TYPE_ID_UINT64: u16 = 2;
/// UTF-16 string claim value type.
pub const CLAIM_TYPE_ID_STRING: u16 = 3;
/// Boolean claim value type.
pub const CLAIM_TYPE_ID_BOOLEAN: u16 = 6;

const PAC_HEADER_LEN: usize = 8;
const PAC_INFO_BUFFER_LEN: usize = 16;
const PAC_SERVER_CHECKSUM_KEY_USAGE: u32 = 17;
const PAC_CREDENTIALS_KEY_USAGE: u32 = 16;
const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_SECONDS: u64 = 11_644_473_600;
const MAX_REASONABLE_NDR_COUNT: u32 = 1_000_000;

/// NTLM supplemental credential LM OWF flag index.
pub const NTLM_SUPPLEMENTAL_CRED_LMOWF: u32 = 31;
/// NTLM supplemental credential NT OWF flag index.
pub const NTLM_SUPPLEMENTAL_CRED_NTOWF: u32 = 30;

/// Parsed PAC container and selected processed buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pac {
    /// Number of PAC info buffers.
    pub c_buffers: u32,
    /// PAC version, normally zero.
    pub version: u32,
    /// PAC info buffer table.
    pub buffers: Vec<InfoBuffer>,
    /// Original PAC bytes.
    pub data: Vec<u8>,
    /// PAC bytes with server and KDC signature bytes zeroed.
    pub zero_signature_data: Vec<u8>,
    /// Parsed `KERB_VALIDATION_INFO`, if present and processed.
    pub kerb_validation_info: Option<KerbValidationInfo>,
    /// Parsed server checksum, if present and processed.
    pub server_checksum: Option<SignatureData>,
    /// Parsed KDC checksum, if present and processed.
    pub kdc_checksum: Option<SignatureData>,
    /// Parsed credentials info, if present and processed.
    ///
    /// The encrypted nested credential data still requires the AS reply key.
    pub credentials_info: Option<CredentialsInfo>,
    /// Parsed client info, if present and processed.
    pub client_info: Option<ClientInfo>,
    /// Parsed UPN/DNS info, if present and processed.
    pub upn_dns_info: Option<UpnDnsInfo>,
    /// Parsed S4U delegation info, if present and processed.
    pub s4u_delegation_info: Option<S4UDelegationInfo>,
    /// Parsed device info, if present and processed.
    pub device_info: Option<DeviceInfo>,
    /// Parsed client claims info, if present and processed.
    pub client_claims_info: Option<ClaimsInfo>,
    /// Parsed device claims info, if present and processed.
    pub device_claims_info: Option<ClaimsInfo>,
}

impl Pac {
    /// Parse the PAC header and info buffer table.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let c_buffers = reader.read_u32()?;
        let version = reader.read_u32()?;
        let table_len = usize::try_from(c_buffers)
            .map_err(|_| Error::LengthOverflow)?
            .checked_mul(PAC_INFO_BUFFER_LEN)
            .ok_or(Error::LengthOverflow)?;
        let minimum = PAC_HEADER_LEN
            .checked_add(table_len)
            .ok_or(Error::LengthOverflow)?;
        if bytes.len() < minimum {
            return Err(Error::TooShort {
                target: "PAC info buffer table",
                minimum,
                actual: bytes.len(),
            });
        }

        let mut buffers = Vec::with_capacity(c_buffers as usize);
        for _ in 0..c_buffers {
            buffers.push(InfoBuffer {
                ul_type: reader.read_u32()?,
                cb_buffer_size: reader.read_u32()?,
                offset: reader.read_u64()?,
            });
        }

        for buffer in &buffers {
            buffer.validate(bytes.len())?;
        }

        Ok(Self {
            c_buffers,
            version,
            buffers,
            data: bytes.to_vec(),
            zero_signature_data: bytes.to_vec(),
            kerb_validation_info: None,
            server_checksum: None,
            kdc_checksum: None,
            credentials_info: None,
            client_info: None,
            upn_dns_info: None,
            s4u_delegation_info: None,
            device_info: None,
            client_claims_info: None,
            device_claims_info: None,
        })
    }

    /// Parse the PAC header and process recognized PAC info buffers.
    pub fn parse_and_process(bytes: &[u8]) -> Result<Self, Error> {
        let mut pac = Self::parse(bytes)?;
        pac.process_buffers()?;
        Ok(pac)
    }

    /// Process recognized PAC info buffers.
    ///
    /// Unknown and currently unsupported PAC buffers are left in the raw buffer
    /// table and skipped here.
    pub fn process_buffers(&mut self) -> Result<(), Error> {
        for buffer in &self.buffers {
            let bytes = buffer.slice(&self.data)?;
            match buffer.ul_type {
                INFO_TYPE_KERB_VALIDATION_INFO if self.kerb_validation_info.is_none() => {
                    self.kerb_validation_info = Some(KerbValidationInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_SERVER_SIGNATURE_DATA if self.server_checksum.is_none() => {
                    let checksum = SignatureData::parse(bytes)?;
                    buffer.copy_zeroed_signature(&mut self.zero_signature_data, &checksum)?;
                    self.server_checksum = Some(checksum);
                }
                INFO_TYPE_PAC_KDC_SIGNATURE_DATA if self.kdc_checksum.is_none() => {
                    let checksum = SignatureData::parse(bytes)?;
                    buffer.copy_zeroed_signature(&mut self.zero_signature_data, &checksum)?;
                    self.kdc_checksum = Some(checksum);
                }
                INFO_TYPE_CREDENTIALS if self.credentials_info.is_none() => {
                    self.credentials_info = Some(CredentialsInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_CLIENT_INFO if self.client_info.is_none() => {
                    self.client_info = Some(ClientInfo::parse(bytes)?);
                }
                INFO_TYPE_UPN_DNS_INFO if self.upn_dns_info.is_none() => {
                    self.upn_dns_info = Some(UpnDnsInfo::parse(bytes)?);
                }
                INFO_TYPE_S4U_DELEGATION_INFO if self.s4u_delegation_info.is_none() => {
                    self.s4u_delegation_info = Some(S4UDelegationInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_DEVICE_INFO if self.device_info.is_none() => {
                    self.device_info = Some(DeviceInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_CLIENT_CLAIMS_INFO if self.client_claims_info.is_none() => {
                    self.client_claims_info = Some(ClaimsInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_DEVICE_CLAIMS_INFO if self.device_claims_info.is_none() => {
                    self.device_claims_info = Some(ClaimsInfo::parse(bytes)?);
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Verify required service-side PAC buffers and the server checksum.
    pub fn verify(&self, key: &EncryptionKey) -> Result<(), Error> {
        self.require_service_buffers()?;
        if !self.verify_server_checksum(key)? {
            return Err(Error::ServerChecksumVerificationFailed);
        }
        Ok(())
    }

    /// Verify the server checksum over the zero-signature PAC bytes.
    pub fn verify_server_checksum(&self, key: &EncryptionKey) -> Result<bool, Error> {
        let checksum = self
            .server_checksum
            .as_ref()
            .ok_or(Error::MissingRequiredBuffer("ServerChecksum"))?;
        let etype = kerberos_etype_for_checksum_type(checksum.signature_type)
            .ok_or(Error::UnsupportedChecksumType(checksum.signature_type))?;
        if key.etype != etype.etype_id() {
            return Ok(false);
        }
        Ok(etype.verify_checksum(
            &key.value,
            &self.zero_signature_data,
            &checksum.signature,
            PAC_SERVER_CHECKSUM_KEY_USAGE,
        ))
    }

    /// Return an info buffer by type.
    pub fn buffer(&self, ul_type: u32) -> Option<&InfoBuffer> {
        self.buffers.iter().find(|buffer| buffer.ul_type == ul_type)
    }

    /// Return the raw bytes for an info buffer.
    pub fn buffer_bytes(&self, buffer: &InfoBuffer) -> Result<&[u8], Error> {
        buffer.slice(&self.data)
    }

    fn require_service_buffers(&self) -> Result<(), Error> {
        if self.kerb_validation_info.is_none() {
            return Err(Error::MissingRequiredBuffer("KerbValidationInfo"));
        }
        if self.server_checksum.is_none() {
            return Err(Error::MissingRequiredBuffer("ServerChecksum"));
        }
        if self.kdc_checksum.is_none() {
            return Err(Error::MissingRequiredBuffer("KDCChecksum"));
        }
        if self.client_info.is_none() {
            return Err(Error::MissingRequiredBuffer("ClientInfo"));
        }
        Ok(())
    }
}

/// Extract and process the first `AD-WIN2K-PAC` entry from Kerberos
/// authorization data.
#[cfg(feature = "messages")]
pub fn find_pac_in_authorization_data(
    authorization_data: &rasn_kerberos::AuthorizationData,
) -> Result<Option<Pac>, Error> {
    for entry in authorization_data.iter() {
        match entry.r#type {
            AD_WIN2K_PAC => return Ok(Some(Pac::parse_and_process(entry.data.as_ref())?)),
            AD_IF_RELEVANT => {
                let nested =
                    rasn::der::decode::<rasn_kerberos::AuthorizationData>(entry.data.as_ref())
                        .map_err(|error| Error::DerDecode(error.to_string()))?;
                if let Some(pac) = find_pac_in_authorization_data(&nested)? {
                    return Ok(Some(pac));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// PAC info buffer table entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfoBuffer {
    /// Type of the PAC data at `offset`.
    pub ul_type: u32,
    /// Size of the PAC data at `offset`.
    pub cb_buffer_size: u32,
    /// Offset from the beginning of the PAC to the data.
    pub offset: u64,
}

impl InfoBuffer {
    fn validate(&self, total_len: usize) -> Result<(), Error> {
        if !self.offset.is_multiple_of(8) {
            return Err(Error::BufferOffsetNotAligned {
                ul_type: self.ul_type,
                offset: self.offset,
            });
        }
        let offset = usize::try_from(self.offset).map_err(|_| Error::LengthOverflow)?;
        let len = usize::try_from(self.cb_buffer_size).map_err(|_| Error::LengthOverflow)?;
        offset
            .checked_add(len)
            .filter(|end| *end <= total_len)
            .ok_or(Error::BufferOutOfBounds {
                ul_type: self.ul_type,
                offset: self.offset,
                len: self.cb_buffer_size,
                total_len,
            })?;
        Ok(())
    }

    fn slice<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], Error> {
        self.validate(data.len())?;
        let offset = usize::try_from(self.offset).map_err(|_| Error::LengthOverflow)?;
        let len = usize::try_from(self.cb_buffer_size).map_err(|_| Error::LengthOverflow)?;
        Ok(&data[offset..offset + len])
    }

    fn copy_zeroed_signature(
        &self,
        zero_signature_data: &mut [u8],
        signature: &SignatureData,
    ) -> Result<(), Error> {
        let offset = usize::try_from(self.offset).map_err(|_| Error::LengthOverflow)?;
        let len = usize::try_from(self.cb_buffer_size).map_err(|_| Error::LengthOverflow)?;
        let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        if end > zero_signature_data.len() || len != signature.zeroed_data.len() {
            return Err(Error::BufferOutOfBounds {
                ul_type: self.ul_type,
                offset: self.offset,
                len: self.cb_buffer_size,
                total_len: zero_signature_data.len(),
            });
        }
        zero_signature_data[offset..end].copy_from_slice(&signature.zeroed_data);
        Ok(())
    }
}

/// PAC signature data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureData {
    /// PAC checksum type.
    pub signature_type: u32,
    /// Checksum bytes.
    pub signature: Vec<u8>,
    /// Optional RODC identifier.
    pub rodc_identifier: Option<u16>,
    /// Original signature buffer with only checksum bytes zeroed.
    pub zeroed_data: Vec<u8>,
}

impl SignatureData {
    /// Parse PAC signature data.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let signature_type = reader.read_u32()?;
        let signature_len = checksum_signature_len(signature_type)
            .ok_or(Error::UnsupportedChecksumType(signature_type))?;
        let signature = reader.read_bytes(signature_len)?.to_vec();
        let rodc_identifier = if reader.remaining() >= 2 {
            Some(reader.read_u16()?)
        } else {
            None
        };

        let mut zeroed_data = bytes.to_vec();
        zeroed_data[4..4 + signature_len].fill(0);

        Ok(Self {
            signature_type,
            signature,
            rodc_identifier,
            zeroed_data,
        })
    }
}

/// PAC client info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientInfo {
    /// TGT authentication time.
    pub client_id: FileTime,
    /// Client account name length in bytes.
    pub name_length: u16,
    /// Client account name.
    pub name: String,
}

impl ClientInfo {
    /// Parse PAC client info.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let client_id = reader.read_filetime()?;
        let name_length = reader.read_u16()?;
        let name_bytes = reader.read_bytes(name_length.into())?;
        let name = utf16le_bytes_to_string(name_bytes, "ClientInfo.Name")?;
        Ok(Self {
            client_id,
            name_length,
            name,
        })
    }
}

/// PAC UPN/DNS info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpnDnsInfo {
    /// UPN length in bytes.
    pub upn_length: u16,
    /// UPN offset from the start of this buffer.
    pub upn_offset: u16,
    /// DNS domain name length in bytes.
    pub dns_domain_name_length: u16,
    /// DNS domain name offset from the start of this buffer.
    pub dns_domain_name_offset: u16,
    /// UPN/DNS flags.
    pub flags: u32,
    /// User principal name.
    pub upn: String,
    /// DNS domain name.
    pub dns_domain: String,
}

impl UpnDnsInfo {
    /// Parse PAC UPN/DNS info.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let upn_length = reader.read_u16()?;
        let upn_offset = reader.read_u16()?;
        let dns_domain_name_length = reader.read_u16()?;
        let dns_domain_name_offset = reader.read_u16()?;
        let flags = reader.read_u32()?;

        let upn = utf16le_bytes_to_string(
            checked_slice(
                bytes,
                upn_offset.into(),
                upn_length.into(),
                "UPN_DNS_INFO.UPN",
            )?,
            "UPN_DNS_INFO.UPN",
        )?;
        let dns_domain = utf16le_bytes_to_string(
            checked_slice(
                bytes,
                dns_domain_name_offset.into(),
                dns_domain_name_length.into(),
                "UPN_DNS_INFO.DNSDomain",
            )?,
            "UPN_DNS_INFO.DNSDomain",
        )?;

        Ok(Self {
            upn_length,
            upn_offset,
            dns_domain_name_length,
            dns_domain_name_offset,
            flags,
            upn,
            dns_domain,
        })
    }
}

/// PAC credentials info.
///
/// This PAC buffer is not NDR-wrapped. The nested credential data is encrypted
/// with key usage 16 and normally requires the AS reply key, so service-side PAC
/// processing records the encrypted bytes without decrypting them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialsInfo {
    /// Credentials info version. The Microsoft format requires zero.
    pub version: u32,
    /// Kerberos encryption type used for the encrypted credential data.
    pub encryption_type: u32,
    /// Encrypted NDR-encoded `CredentialData`.
    pub encrypted_credential_data: Vec<u8>,
}

impl CredentialsInfo {
    /// Parse PAC credentials info without decrypting the nested credential data.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let version = reader.read_u32()?;
        if version != 0 {
            return Err(Error::InvalidCredentialsInfoVersion(version));
        }
        let encryption_type = reader.read_u32()?;
        let encrypted_credential_data = reader.read_bytes(reader.remaining())?.to_vec();

        Ok(Self {
            version,
            encryption_type,
            encrypted_credential_data,
        })
    }

    /// Decrypt and parse the nested PAC credential data.
    pub fn decrypt_credential_data(&self, key: &EncryptionKey) -> Result<CredentialData, Error> {
        let encryption_type =
            i32::try_from(self.encryption_type).map_err(|_| Error::LengthOverflow)?;
        if key.etype != encryption_type {
            return Err(Error::CredentialKeyTypeMismatch {
                expected: encryption_type,
                actual: key.etype,
            });
        }
        let etype = KerberosEtype::from_etype_id(encryption_type)
            .ok_or(Error::UnsupportedEncryptionType(encryption_type))?;
        let plaintext = etype.decrypt_message(
            &key.value,
            &self.encrypted_credential_data,
            PAC_CREDENTIALS_KEY_USAGE,
        )?;
        CredentialData::parse(&plaintext)
    }
}

/// Decrypted PAC credential data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialData {
    /// Number of supplemental credentials.
    pub credential_count: u32,
    /// Supplemental credentials.
    pub credentials: Vec<SecpkgSupplementalCredential>,
}

impl CredentialData {
    /// Parse NDR-encoded PAC credential data.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "CredentialData")?;

        let credential_count = read_ndr_u32(&mut reader)?;
        let credentials = read_counted_supplemental_credentials(&mut reader, credential_count)?;
        ensure_zero_trailing(&mut reader, "CredentialData")?;

        Ok(Self {
            credential_count,
            credentials,
        })
    }
}

/// Supplemental credential package entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecpkgSupplementalCredential {
    /// Supplemental credential package name.
    pub package_name: RpcUnicodeString,
    /// Credential byte length.
    pub credential_size: u32,
    /// Package-specific credential bytes.
    pub credentials: Vec<u8>,
}

/// NTLM supplemental credential data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtlmSupplementalCredential {
    /// NTLM supplemental credential version. The Microsoft format requires zero.
    pub version: u32,
    /// NTLM supplemental credential flags.
    pub flags: u32,
    /// LM one-way function, if present and valid.
    pub lm_password: Option<[u8; 16]>,
    /// NT one-way function, if present and valid.
    pub nt_password: Option<[u8; 16]>,
}

impl NtlmSupplementalCredential {
    /// Parse package-specific NTLM supplemental credential bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let version = reader.read_u32()?;
        if version != 0 {
            return Err(Error::InvalidNtlmSupplementalCredentialVersion(version));
        }
        let flags = reader.read_u32()?;
        let lm_password = if ntlm_supplemental_flag_set(flags, NTLM_SUPPLEMENTAL_CRED_LMOWF) {
            Some(
                reader
                    .read_bytes(16)?
                    .try_into()
                    .expect("16-byte slice converts to array"),
            )
        } else {
            None
        };
        let nt_password = if ntlm_supplemental_flag_set(flags, NTLM_SUPPLEMENTAL_CRED_NTOWF) {
            Some(
                reader
                    .read_bytes(16)?
                    .try_into()
                    .expect("16-byte slice converts to array"),
            )
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            lm_password,
            nt_password,
        })
    }

    /// Whether the LM OWF flag is set.
    pub fn has_lm_password(&self) -> bool {
        ntlm_supplemental_flag_set(self.flags, NTLM_SUPPLEMENTAL_CRED_LMOWF)
    }

    /// Whether the NT OWF flag is set.
    pub fn has_nt_password(&self) -> bool {
        ntlm_supplemental_flag_set(self.flags, NTLM_SUPPLEMENTAL_CRED_NTOWF)
    }
}

/// PAC S4U delegation information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S4UDelegationInfo {
    /// Principal to which the application can forward the ticket.
    pub s4u2proxy_target: RpcUnicodeString,
    /// Number of transited services.
    pub transited_list_size: u32,
    /// Delegated services transited by the client and subsequent services.
    pub s4u_transited_services: Vec<RpcUnicodeString>,
}

impl S4UDelegationInfo {
    /// Parse NDR-encoded S4U delegation information.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "S4UDelegationInfo")?;

        let s4u2proxy_target = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let transited_list_size = read_ndr_u32(&mut reader)?;
        let s4u_transited_services_ref = read_ndr_u32(&mut reader)?;

        let s4u2proxy_target =
            read_deferred_unicode_string(&mut reader, s4u2proxy_target, "S4U2proxyTarget")?;
        let s4u_transited_services = read_deferred_rpc_unicode_strings(
            &mut reader,
            s4u_transited_services_ref,
            transited_list_size,
            "S4UTransitedServices",
        )?;
        ensure_zero_trailing(&mut reader, "S4UDelegationInfo")?;

        Ok(Self {
            s4u2proxy_target,
            transited_list_size,
            s4u_transited_services,
        })
    }
}

/// PAC device information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    /// Device account RID.
    pub user_id: u32,
    /// Device primary group RID.
    pub primary_group_id: u32,
    /// Domain SID for the device account.
    pub account_domain_id: Option<Sid>,
    /// Number of account-domain groups.
    pub account_group_count: u32,
    /// Account-domain group memberships.
    pub account_group_ids: Vec<GroupMembership>,
    /// Number of extra SIDs.
    pub sid_count: u32,
    /// Extra SIDs for groups outside the account domain.
    pub extra_sids: Vec<SidAndAttributes>,
    /// Number of domain group sets.
    pub domain_group_count: u32,
    /// Domain group memberships.
    pub domain_group: Vec<DomainGroupMembership>,
}

impl DeviceInfo {
    /// Parse NDR-encoded PAC device information.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "DeviceInfo")?;

        let user_id = read_ndr_u32(&mut reader)?;
        let primary_group_id = read_ndr_u32(&mut reader)?;
        let account_domain_id_ref = read_ndr_u32(&mut reader)?;
        let account_group_count = read_ndr_u32(&mut reader)?;
        let account_group_ids_ref = read_ndr_u32(&mut reader)?;
        let sid_count = read_ndr_u32(&mut reader)?;
        let extra_sids_ref = read_ndr_u32(&mut reader)?;
        let domain_group_count = read_ndr_u32(&mut reader)?;
        let domain_group_ref = read_ndr_u32(&mut reader)?;

        let account_domain_id = read_deferred_sid(
            &mut reader,
            account_domain_id_ref,
            "DeviceInfo.AccountDomainID",
        )?;
        let account_group_ids = read_deferred_group_memberships(
            &mut reader,
            account_group_ids_ref,
            account_group_count,
            "DeviceInfo.AccountGroupIDs",
        )?;
        let extra_sids = read_deferred_sid_and_attributes(
            &mut reader,
            extra_sids_ref,
            sid_count,
            "DeviceInfo.ExtraSIDs",
        )?;
        let domain_group = read_deferred_domain_group_memberships(
            &mut reader,
            domain_group_ref,
            domain_group_count,
            "DeviceInfo.DomainGroup",
        )?;
        ensure_zero_trailing(&mut reader, "DeviceInfo")?;

        Ok(Self {
            user_id,
            primary_group_id,
            account_domain_id,
            account_group_count,
            account_group_ids,
            sid_count,
            extra_sids,
            domain_group_count,
            domain_group,
        })
    }

    /// Return SIDs for account-domain groups, extra SIDs, and domain groups.
    pub fn group_membership_sids(&self) -> Vec<String> {
        let mut sids = Vec::new();
        if let Some(account_domain_sid) = &self.account_domain_id {
            for group in &self.account_group_ids {
                sids.push(format!("{account_domain_sid}-{}", group.relative_id));
            }
        }
        for extra_sid in &self.extra_sids {
            let sid = extra_sid.sid.to_string();
            if !sids.iter().any(|existing| existing == &sid) {
                sids.push(sid);
            }
        }
        for domain_group in &self.domain_group {
            for group in &domain_group.group_ids {
                let sid = format!("{}-{}", domain_group.domain_id, group.relative_id);
                if !sids.iter().any(|existing| existing == &sid) {
                    sids.push(sid);
                }
            }
        }
        sids
    }
}

/// PAC client or device claims info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsInfo {
    /// Claims metadata, including compression and raw nested claims bytes.
    pub metadata: ClaimsSetMetadata,
    /// Decoded claims set.
    pub claims_set: ClaimsSet,
}

impl ClaimsInfo {
    /// Parse PAC client or device claims info.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let metadata = ClaimsSetMetadata::parse(bytes)?;
        let claims_set = metadata.claims_set()?;
        Ok(Self {
            metadata,
            claims_set,
        })
    }
}

/// Claims set metadata wrapping a nested claims set byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsSetMetadata {
    /// Encoded claims set byte length.
    pub claims_set_size: u32,
    /// Encoded claims set bytes.
    pub claims_set_bytes: Vec<u8>,
    /// Compression format for `claims_set_bytes`.
    pub compression_format: u16,
    /// Uncompressed claims set byte length.
    pub uncompressed_claims_set_size: u32,
    /// Reserved field type.
    pub reserved_type: u16,
    /// Reserved field byte length.
    pub reserved_field_size: u32,
    /// Reserved field bytes.
    pub reserved_field: Vec<u8>,
}

impl ClaimsSetMetadata {
    /// Parse an NDR-encoded `ClaimsSetMetadata` value.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "ClaimsSetMetadata")?;

        let claims_set_size = read_ndr_u32(&mut reader)?;
        let claims_set_bytes_ref = read_ndr_u32(&mut reader)?;
        let compression_format = read_ndr_u16(&mut reader)?;
        let uncompressed_claims_set_size = read_ndr_u32(&mut reader)?;
        let reserved_type = read_ndr_u16(&mut reader)?;
        let reserved_field_size = read_ndr_u32(&mut reader)?;
        let reserved_field_ref = read_ndr_u32(&mut reader)?;

        let claims_set_bytes = read_deferred_u8_array(
            &mut reader,
            claims_set_bytes_ref,
            claims_set_size,
            "ClaimsSetMetadata.ClaimsSetBytes",
        )?;
        let reserved_field = read_deferred_u8_array(
            &mut reader,
            reserved_field_ref,
            reserved_field_size,
            "ClaimsSetMetadata.ReservedField",
        )?;
        ensure_zero_trailing(&mut reader, "ClaimsSetMetadata")?;

        Ok(Self {
            claims_set_size,
            claims_set_bytes,
            compression_format,
            uncompressed_claims_set_size,
            reserved_type,
            reserved_field_size,
            reserved_field,
        })
    }

    /// Decode the nested claims set bytes, decompressing when required.
    pub fn decoded_claims_set_bytes(&self) -> Result<Vec<u8>, Error> {
        match self.compression_format {
            CLAIMS_COMPRESSION_FORMAT_NONE => Ok(self.claims_set_bytes.clone()),
            CLAIMS_COMPRESSION_FORMAT_LZNT1 => {
                decompress_claims_set_bytes::<compcol::lznt1::Lznt1>(
                    self.compression_format,
                    &self.claims_set_bytes,
                    self.uncompressed_claims_set_size,
                )
            }
            CLAIMS_COMPRESSION_FORMAT_XPRESS => {
                let mut framed = Vec::with_capacity(8 + self.claims_set_bytes.len());
                framed
                    .extend_from_slice(&u64::from(self.uncompressed_claims_set_size).to_le_bytes());
                framed.extend_from_slice(&self.claims_set_bytes);
                decompress_claims_set_bytes::<compcol::xpress::Xpress>(
                    self.compression_format,
                    &framed,
                    self.uncompressed_claims_set_size,
                )
            }
            CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF => {
                let mut framed = Vec::with_capacity(4 + self.claims_set_bytes.len());
                framed.extend_from_slice(&self.uncompressed_claims_set_size.to_le_bytes());
                framed.extend_from_slice(&self.claims_set_bytes);
                decompress_claims_set_bytes::<compcol::xpress_huffman::XpressHuffman>(
                    self.compression_format,
                    &framed,
                    self.uncompressed_claims_set_size,
                )
            }
            compression_format => Err(Error::UnsupportedClaimsCompressionFormat(
                compression_format,
            )),
        }
    }

    /// Decode the nested claims set.
    pub fn claims_set(&self) -> Result<ClaimsSet, Error> {
        ClaimsSet::parse(&self.decoded_claims_set_bytes()?)
    }
}

/// Decoded PAC claims set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsSet {
    /// Number of claims arrays.
    pub claims_array_count: u32,
    /// Claims arrays.
    pub claims_arrays: Vec<ClaimsArray>,
    /// Reserved field type.
    pub reserved_type: u16,
    /// Reserved field byte length.
    pub reserved_field_size: u32,
    /// Reserved field bytes.
    pub reserved_field: Vec<u8>,
}

impl ClaimsSet {
    /// Parse an NDR-encoded claims set.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "ClaimsSet")?;

        let claims_array_count = read_ndr_u32(&mut reader)?;
        let claims_arrays_ref = read_ndr_u32(&mut reader)?;
        let reserved_type = read_ndr_u16(&mut reader)?;
        let reserved_field_size = read_ndr_u32(&mut reader)?;
        let reserved_field_ref = read_ndr_u32(&mut reader)?;

        let claims_arrays = read_deferred_claims_arrays(
            &mut reader,
            claims_arrays_ref,
            claims_array_count,
            "ClaimsSet.ClaimsArrays",
        )?;
        let reserved_field = read_deferred_u8_array(
            &mut reader,
            reserved_field_ref,
            reserved_field_size,
            "ClaimsSet.ReservedField",
        )?;
        ensure_zero_trailing(&mut reader, "ClaimsSet")?;

        Ok(Self {
            claims_array_count,
            claims_arrays,
            reserved_type,
            reserved_field_size,
            reserved_field,
        })
    }
}

/// Claims from a single source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsArray {
    /// Claims source type.
    pub claims_source_type: u16,
    /// Number of claim entries.
    pub claims_count: u32,
    /// Claim entries.
    pub claim_entries: Vec<ClaimEntry>,
}

/// A single decoded claim entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEntry {
    /// Claim identifier URI.
    pub id: String,
    /// Claim value type.
    pub claim_type: u16,
    /// Claim values.
    pub values: ClaimValues,
}

/// Typed claim values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimValues {
    /// Signed 64-bit integer values.
    Int64(Vec<i64>),
    /// Unsigned 64-bit integer values.
    UInt64(Vec<u64>),
    /// UTF-16 string values.
    String(Vec<String>),
    /// Boolean values.
    Boolean(Vec<bool>),
}

impl ClaimValues {
    /// Number of values.
    pub fn len(&self) -> usize {
        match self {
            Self::Int64(values) => values.len(),
            Self::UInt64(values) => values.len(),
            Self::String(values) => values.len(),
            Self::Boolean(values) => values.len(),
        }
    }

    /// Whether the claim carries no values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Microsoft FILETIME, expressed as 100ns ticks since 1601-01-01 UTC.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FileTime {
    ticks: u64,
}

impl FileTime {
    /// Build from raw Windows FILETIME ticks.
    pub fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    /// Raw Windows FILETIME ticks.
    pub fn ticks(self) -> u64 {
        self.ticks
    }

    /// Convert to `SystemTime`.
    pub fn system_time(self) -> SystemTime {
        let unix_epoch_ticks = WINDOWS_TO_UNIX_SECONDS * WINDOWS_TICKS_PER_SECOND;
        if self.ticks >= unix_epoch_ticks {
            UNIX_EPOCH + filetime_tick_duration(self.ticks - unix_epoch_ticks)
        } else {
            UNIX_EPOCH - filetime_tick_duration(unix_epoch_ticks - self.ticks)
        }
    }
}

/// RPC Unicode string decoded from NDR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcUnicodeString {
    /// String length in bytes.
    pub length: u16,
    /// Maximum string length in bytes.
    pub maximum_length: u16,
    /// Decoded string value.
    pub value: String,
}

/// PAC group membership entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMembership {
    /// Relative identifier.
    pub relative_id: u32,
    /// Group attributes.
    pub attributes: u32,
}

/// Windows SID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sid {
    /// SID revision.
    pub revision: u8,
    /// Identifier authority bytes.
    pub identifier_authority: [u8; 6],
    /// SID sub-authorities.
    pub sub_authorities: Vec<u32>,
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut authority = 0u64;
        for byte in self.identifier_authority {
            authority = (authority << 8) | u64::from(byte);
        }
        if authority > u64::from(u32::MAX) {
            write!(f, "S-{}-0x", self.revision)?;
            for byte in self.identifier_authority {
                write!(f, "{byte:02x}")?;
            }
        } else {
            write!(f, "S-{}-{}", self.revision, authority)?;
        }
        for sub_authority in &self.sub_authorities {
            write!(f, "-{sub_authority}")?;
        }
        Ok(())
    }
}

/// SID with attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidAndAttributes {
    /// SID.
    pub sid: Sid,
    /// SID attributes.
    pub attributes: u32,
}

/// Device domain group memberships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainGroupMembership {
    /// Domain SID.
    pub domain_id: Sid,
    /// Number of group memberships in `group_ids`.
    pub group_count: u32,
    /// Groups within `domain_id`.
    pub group_ids: Vec<GroupMembership>,
}

/// Parsed KERB_VALIDATION_INFO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KerbValidationInfo {
    /// User logon time.
    pub logon_time: FileTime,
    /// User logoff time.
    pub logoff_time: FileTime,
    /// Kickoff time.
    pub kickoff_time: FileTime,
    /// Password last set time.
    pub password_last_set: FileTime,
    /// Password can change time.
    pub password_can_change: FileTime,
    /// Password must change time.
    pub password_must_change: FileTime,
    /// Effective user name.
    pub effective_name: RpcUnicodeString,
    /// Full user name.
    pub full_name: RpcUnicodeString,
    /// Logon script.
    pub logon_script: RpcUnicodeString,
    /// Profile path.
    pub profile_path: RpcUnicodeString,
    /// Home directory.
    pub home_directory: RpcUnicodeString,
    /// Home directory drive.
    pub home_directory_drive: RpcUnicodeString,
    /// Logon count.
    pub logon_count: u16,
    /// Bad password count.
    pub bad_password_count: u16,
    /// User RID.
    pub user_id: u32,
    /// Primary group RID.
    pub primary_group_id: u32,
    /// Group count.
    pub group_count: u32,
    /// Group memberships.
    pub group_ids: Vec<GroupMembership>,
    /// User flags.
    pub user_flags: u32,
    /// User session key bytes.
    pub user_session_key: [u8; 16],
    /// Logon server.
    pub logon_server: RpcUnicodeString,
    /// Logon domain name.
    pub logon_domain_name: RpcUnicodeString,
    /// Logon domain SID.
    pub logon_domain_id: Option<Sid>,
    /// Reserved values.
    pub reserved1: [u32; 2],
    /// User account control flags.
    pub user_account_control: u32,
    /// Sub-authentication status.
    pub sub_auth_status: u32,
    /// Last successful interactive logon.
    pub last_successful_ilogon: FileTime,
    /// Last failed interactive logon.
    pub last_failed_ilogon: FileTime,
    /// Failed interactive logon count.
    pub failed_ilogon_count: u32,
    /// Reserved value.
    pub reserved3: u32,
    /// Extra SID count.
    pub sid_count: u32,
    /// Extra SIDs.
    pub extra_sids: Vec<SidAndAttributes>,
    /// Resource group domain SID.
    pub resource_group_domain_sid: Option<Sid>,
    /// Resource group count.
    pub resource_group_count: u32,
    /// Resource groups.
    pub resource_group_ids: Vec<GroupMembership>,
}

impl KerbValidationInfo {
    /// Parse NDR-encoded KERB_VALIDATION_INFO.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "KERB_VALIDATION_INFO")?;

        let logon_time = reader.read_filetime()?;
        let logoff_time = reader.read_filetime()?;
        let kickoff_time = reader.read_filetime()?;
        let password_last_set = reader.read_filetime()?;
        let password_can_change = reader.read_filetime()?;
        let password_must_change = reader.read_filetime()?;

        let effective_name = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let full_name = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let logon_script = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let profile_path = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let home_directory = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let home_directory_drive = RpcUnicodeStringDescriptor::read(&mut reader)?;

        let logon_count = reader.read_u16()?;
        let bad_password_count = reader.read_u16()?;
        let user_id = reader.read_u32()?;
        let primary_group_id = reader.read_u32()?;
        let group_count = reader.read_u32()?;
        let group_ids_ref = reader.read_u32()?;
        let user_flags = reader.read_u32()?;
        let user_session_key: [u8; 16] = reader
            .read_bytes(16)?
            .try_into()
            .expect("16-byte slice converts to array");

        let logon_server = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let logon_domain_name = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let logon_domain_id_ref = reader.read_u32()?;
        let reserved1 = [reader.read_u32()?, reader.read_u32()?];
        let user_account_control = reader.read_u32()?;
        let sub_auth_status = reader.read_u32()?;
        let last_successful_ilogon = reader.read_filetime()?;
        let last_failed_ilogon = reader.read_filetime()?;
        let failed_ilogon_count = reader.read_u32()?;
        let reserved3 = reader.read_u32()?;
        let sid_count = reader.read_u32()?;
        let extra_sids_ref = reader.read_u32()?;
        let resource_group_domain_sid_ref = reader.read_u32()?;
        let resource_group_count = reader.read_u32()?;
        let resource_group_ids_ref = reader.read_u32()?;

        let effective_name =
            read_deferred_unicode_string(&mut reader, effective_name, "EffectiveName")?;
        let full_name = read_deferred_unicode_string(&mut reader, full_name, "FullName")?;
        let logon_script = read_deferred_unicode_string(&mut reader, logon_script, "LogonScript")?;
        let profile_path = read_deferred_unicode_string(&mut reader, profile_path, "ProfilePath")?;
        let home_directory =
            read_deferred_unicode_string(&mut reader, home_directory, "HomeDirectory")?;
        let home_directory_drive =
            read_deferred_unicode_string(&mut reader, home_directory_drive, "HomeDirectoryDrive")?;
        let group_ids =
            read_deferred_group_memberships(&mut reader, group_ids_ref, group_count, "GroupIDs")?;
        let logon_server = read_deferred_unicode_string(&mut reader, logon_server, "LogonServer")?;
        let logon_domain_name =
            read_deferred_unicode_string(&mut reader, logon_domain_name, "LogonDomainName")?;
        let logon_domain_id = read_deferred_sid(&mut reader, logon_domain_id_ref, "LogonDomainID")?;
        let extra_sids =
            read_deferred_sid_and_attributes(&mut reader, extra_sids_ref, sid_count, "ExtraSIDs")?;
        let resource_group_domain_sid = read_deferred_sid(
            &mut reader,
            resource_group_domain_sid_ref,
            "ResourceGroupDomainSID",
        )?;
        let resource_group_ids = read_deferred_group_memberships(
            &mut reader,
            resource_group_ids_ref,
            resource_group_count,
            "ResourceGroupIDs",
        )?;

        reader.align(4)?;
        if reader.remaining_bytes().iter().any(|byte| *byte != 0) {
            return Err(Error::TrailingNdrBytes {
                remaining: reader.remaining(),
            });
        }

        Ok(Self {
            logon_time,
            logoff_time,
            kickoff_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            full_name,
            logon_script,
            profile_path,
            home_directory,
            home_directory_drive,
            logon_count,
            bad_password_count,
            user_id,
            primary_group_id,
            group_count,
            group_ids,
            user_flags,
            user_session_key,
            logon_server,
            logon_domain_name,
            logon_domain_id,
            reserved1,
            user_account_control,
            sub_auth_status,
            last_successful_ilogon,
            last_failed_ilogon,
            failed_ilogon_count,
            reserved3,
            sid_count,
            extra_sids,
            resource_group_domain_sid,
            resource_group_count,
            resource_group_ids,
        })
    }

    /// Return SIDs for domain groups, extra SIDs, and resource groups.
    pub fn group_membership_sids(&self) -> Vec<String> {
        let mut sids = Vec::new();
        if let Some(domain_sid) = &self.logon_domain_id {
            for group in &self.group_ids {
                sids.push(format!("{domain_sid}-{}", group.relative_id));
            }
        }
        for extra_sid in &self.extra_sids {
            let sid = extra_sid.sid.to_string();
            if !sids.iter().any(|existing| existing == &sid) {
                sids.push(sid);
            }
        }
        if let Some(resource_domain_sid) = &self.resource_group_domain_sid {
            for group in &self.resource_group_ids {
                let sid = format!("{resource_domain_sid}-{}", group.relative_id);
                if !sids.iter().any(|existing| existing == &sid) {
                    sids.push(sid);
                }
            }
        }
        sids
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RpcUnicodeStringDescriptor {
    length: u16,
    maximum_length: u16,
    referent_id: u32,
}

impl RpcUnicodeStringDescriptor {
    fn read(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            length: reader.read_u16()?,
            maximum_length: reader.read_u16()?,
            referent_id: reader.read_u32()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimsArrayDescriptor {
    claims_source_type: u16,
    claims_count: u32,
    claim_entries_ref: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimEntryDescriptor {
    id_ref: u32,
    claim_type: u16,
    value_count: u32,
    values_ref: u32,
}

fn read_ndr_wrapper(reader: &mut Reader<'_>, target: &'static str) -> Result<(), Error> {
    let minimum = 20;
    if reader.bytes.len() < minimum {
        return Err(Error::TooShort {
            target,
            minimum,
            actual: reader.bytes.len(),
        });
    }

    let integer_endian = reader.read_u8()?;
    let character_set = reader.read_u8()?;
    let floating_point = reader.read_u8()?;
    let reserved = reader.read_u8()?;
    if integer_endian != 1 || character_set != 0x10 || floating_point != 0x08 || reserved != 0 {
        return Err(Error::InvalidNdrHeader);
    }

    let _fill = reader.read_u32()?;
    let object_len = reader.read_u32()?;
    let _reserved = reader.read_u32()?;
    let object_len = usize::try_from(object_len).map_err(|_| Error::LengthOverflow)?;
    if object_len > reader.bytes.len().saturating_sub(16) {
        return Err(Error::InvalidNdrObjectLength {
            object_len,
            remaining: reader.bytes.len().saturating_sub(16),
        });
    }

    let top_level_referent = reader.read_u32()?;
    if top_level_referent == 0 {
        return Err(Error::MissingNdrPointer(target));
    }
    Ok(())
}

fn read_ndr_u16(reader: &mut Reader<'_>) -> Result<u16, Error> {
    reader.align(2)?;
    reader.read_u16()
}

fn read_ndr_u32(reader: &mut Reader<'_>) -> Result<u32, Error> {
    reader.align(4)?;
    reader.read_u32()
}

fn read_ndr_u64(reader: &mut Reader<'_>) -> Result<u64, Error> {
    reader.align(8)?;
    reader.read_u64()
}

fn read_ndr_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = read_ndr_u32(reader)?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}

fn read_deferred_u8_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u8>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let bytes = reader.read_bytes(len)?.to_vec();
    reader.align(4)?;
    Ok(bytes)
}

fn read_counted_supplemental_credentials(
    reader: &mut Reader<'_>,
    count: u32,
) -> Result<Vec<SecpkgSupplementalCredential>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push((
            RpcUnicodeStringDescriptor::read(reader)?,
            read_ndr_u32(reader)?,
            read_ndr_u32(reader)?,
        ));
    }

    let mut supplemental_credentials = Vec::with_capacity(count);
    for (package_name, credential_size, credentials_ref) in descriptors {
        let package_name = read_deferred_unicode_string(
            reader,
            package_name,
            "SECPKGSupplementalCred.PackageName",
        )?;
        let credential_bytes = read_deferred_u8_array(
            reader,
            credentials_ref,
            credential_size,
            "SECPKGSupplementalCred.Credentials",
        )?;
        supplemental_credentials.push(SecpkgSupplementalCredential {
            package_name,
            credential_size,
            credentials: credential_bytes,
        });
    }
    Ok(supplemental_credentials)
}

fn read_deferred_rpc_unicode_strings(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<RpcUnicodeString>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(RpcUnicodeStringDescriptor::read(reader)?);
    }

    let mut strings = Vec::with_capacity(count);
    for descriptor in descriptors {
        strings.push(read_deferred_unicode_string(reader, descriptor, target)?);
    }
    Ok(strings)
}

fn read_deferred_claims_arrays(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimsArray>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(ClaimsArrayDescriptor {
            claims_source_type: read_ndr_u16(reader)?,
            claims_count: read_ndr_u32(reader)?,
            claim_entries_ref: read_ndr_u32(reader)?,
        });
    }

    let mut arrays = Vec::with_capacity(count);
    for descriptor in descriptors {
        let claim_entries = read_deferred_claim_entries(
            reader,
            descriptor.claim_entries_ref,
            descriptor.claims_count,
            "ClaimsArray.ClaimEntries",
        )?;
        arrays.push(ClaimsArray {
            claims_source_type: descriptor.claims_source_type,
            claims_count: descriptor.claims_count,
            claim_entries,
        });
    }
    Ok(arrays)
}

fn read_deferred_claim_entries(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimEntry>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(read_claim_entry_descriptor(reader)?);
    }

    let mut entries = Vec::with_capacity(count);
    for descriptor in descriptors {
        let id = read_deferred_claim_string(reader, descriptor.id_ref, "ClaimEntry.ID")?;
        let values = match descriptor.claim_type {
            CLAIM_TYPE_ID_INT64 => ClaimValues::Int64(read_deferred_i64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.Int64Values",
            )?),
            CLAIM_TYPE_ID_UINT64 => ClaimValues::UInt64(read_deferred_u64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.UInt64Values",
            )?),
            CLAIM_TYPE_ID_STRING => ClaimValues::String(read_deferred_lpwstr_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.StringValues",
            )?),
            CLAIM_TYPE_ID_BOOLEAN => ClaimValues::Boolean(read_deferred_bool_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.BooleanValues",
            )?),
            claim_type => return Err(Error::UnsupportedClaimType(claim_type)),
        };
        entries.push(ClaimEntry {
            id,
            claim_type: descriptor.claim_type,
            values,
        });
    }
    Ok(entries)
}

fn read_claim_entry_descriptor(reader: &mut Reader<'_>) -> Result<ClaimEntryDescriptor, Error> {
    let id_ref = read_ndr_u32(reader)?;
    let claim_type = read_ndr_u16(reader)?;
    let union_tag = read_ndr_u16(reader)?;
    if union_tag != claim_type {
        return Err(Error::InvalidClaimUnionTag {
            claim_type,
            union_tag,
        });
    }
    Ok(ClaimEntryDescriptor {
        id_ref,
        claim_type,
        value_count: read_ndr_u32(reader)?,
        values_ref: read_ndr_u32(reader)?,
    })
}

fn read_deferred_i64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<i64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)? as i64);
    }
    Ok(values)
}

fn read_deferred_u64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)?);
    }
    Ok(values)
}

fn read_deferred_bool_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<bool>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.read_u8()? != 0);
    }
    reader.align(4)?;
    Ok(values)
}

fn read_deferred_lpwstr_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<String>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut string_refs = Vec::with_capacity(count);
    for _ in 0..count {
        string_refs.push(read_ndr_u32(reader)?);
    }

    let mut values = Vec::with_capacity(count);
    for string_ref in string_refs {
        values.push(read_deferred_claim_string(reader, string_ref, target)?);
    }
    Ok(values)
}

fn read_deferred_claim_string(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<String, Error> {
    if referent_id == 0 {
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    let offset = read_ndr_u32(reader)?;
    let actual_count = read_ndr_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let actual_count = usize::try_from(actual_count).map_err(|_| Error::LengthOverflow)?;
    let mut units = Vec::with_capacity(actual_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    if units.last().copied() == Some(0) {
        units.pop();
    }
    String::from_utf16(&units).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })
}

fn ensure_zero_trailing(reader: &mut Reader<'_>, target: &'static str) -> Result<(), Error> {
    reader.align(4)?;
    if reader.remaining_bytes().iter().any(|byte| *byte != 0) {
        return Err(Error::TrailingNdrBytesAfter {
            target,
            remaining: reader.remaining(),
        });
    }
    Ok(())
}

fn decompress_claims_set_bytes<A: compcol::Algorithm>(
    compression_format: u16,
    bytes: &[u8],
    uncompressed_size: u32,
) -> Result<Vec<u8>, Error> {
    let decoded = compcol::vec::decompress_to_vec_capped::<A>(bytes, u64::from(uncompressed_size))
        .map_err(|error| Error::ClaimsDecompression {
            compression_format,
            message: error.to_string(),
        })?;
    let actual = decoded.len();
    let expected = usize::try_from(uncompressed_size).map_err(|_| Error::LengthOverflow)?;
    if actual != expected {
        return Err(Error::ClaimsDecompressedSizeMismatch {
            compression_format,
            expected,
            actual,
        });
    }
    Ok(decoded)
}

fn read_deferred_unicode_string(
    reader: &mut Reader<'_>,
    descriptor: RpcUnicodeStringDescriptor,
    target: &'static str,
) -> Result<RpcUnicodeString, Error> {
    if descriptor.maximum_length < descriptor.length {
        return Err(Error::InvalidRpcUnicodeString {
            target,
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
        });
    }
    if !descriptor.length.is_multiple_of(2) {
        return Err(Error::InvalidUtf16Length {
            target,
            bytes: descriptor.length.into(),
        });
    }
    if descriptor.referent_id == 0 {
        return Ok(RpcUnicodeString {
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
            value: String::new(),
        });
    }

    let max_count = read_reasonable_count(reader, target)?;
    let offset = reader.read_u32()?;
    let actual_count = read_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let actual_count = usize::try_from(actual_count).map_err(|_| Error::LengthOverflow)?;
    let mut units = Vec::with_capacity(actual_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    let logical_len = usize::from(descriptor.length / 2);
    if logical_len > units.len() {
        return Err(Error::InvalidRpcUnicodeStringData {
            target,
            expected_units: logical_len,
            actual_units: units.len(),
        });
    }

    let value = String::from_utf16(&units[..logical_len]).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })?;
    Ok(RpcUnicodeString {
        length: descriptor.length,
        maximum_length: descriptor.maximum_length,
        value,
    })
}

fn read_deferred_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<GroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        groups.push(GroupMembership {
            relative_id: reader.read_u32()?,
            attributes: reader.read_u32()?,
        });
    }
    Ok(groups)
}

fn read_deferred_sid(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<Option<Sid>, Error> {
    if referent_id == 0 {
        return Ok(None);
    }

    let max_sub_authority_count = read_reasonable_count(reader, target)?;
    let revision = reader.read_u8()?;
    let sub_authority_count = reader.read_u8()?;
    if revision != 1 {
        return Err(Error::InvalidSidRevision(revision));
    }
    if u32::from(sub_authority_count) > max_sub_authority_count || sub_authority_count > 15 {
        return Err(Error::InvalidSidSubAuthorityCount {
            target,
            max_count: max_sub_authority_count,
            actual_count: sub_authority_count,
        });
    }

    let identifier_authority: [u8; 6] = reader
        .read_bytes(6)?
        .try_into()
        .expect("6-byte slice converts to array");
    let mut sub_authorities = Vec::with_capacity(sub_authority_count.into());
    for _ in 0..sub_authority_count {
        sub_authorities.push(reader.read_u32()?);
    }
    reader.align(4)?;

    Ok(Some(Sid {
        revision,
        identifier_authority,
        sub_authorities,
    }))
}

fn read_deferred_sid_and_attributes(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<SidAndAttributes>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut refs_and_attributes = Vec::with_capacity(count);
    for _ in 0..count {
        refs_and_attributes.push((reader.read_u32()?, reader.read_u32()?));
    }

    let mut out = Vec::with_capacity(count);
    for (sid_ref, attributes) in refs_and_attributes {
        let sid =
            read_deferred_sid(reader, sid_ref, target)?.ok_or(Error::MissingNdrPointer(target))?;
        out.push(SidAndAttributes { sid, attributes });
    }
    Ok(out)
}

fn read_deferred_domain_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<DomainGroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push((reader.read_u32()?, reader.read_u32()?, reader.read_u32()?));
    }

    let mut groups = Vec::with_capacity(count);
    for (domain_id_ref, group_count, group_ids_ref) in descriptors {
        let domain_id = read_deferred_sid(reader, domain_id_ref, target)?
            .ok_or(Error::MissingNdrPointer(target))?;
        let group_ids =
            read_deferred_group_memberships(reader, group_ids_ref, group_count, target)?;
        groups.push(DomainGroupMembership {
            domain_id,
            group_count,
            group_ids,
        });
    }
    Ok(groups)
}

fn read_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = reader.read_u32()?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}

fn checksum_signature_len(signature_type: u32) -> Option<usize> {
    match signature_type {
        CHECKSUM_HMAC_MD5_UNSIGNED => Some(16),
        CHECKSUM_HMAC_SHA1_96_AES128 | CHECKSUM_HMAC_SHA1_96_AES256 => Some(12),
        CHECKSUM_HMAC_SHA256_128_AES128 => Some(16),
        CHECKSUM_HMAC_SHA384_192_AES256 => Some(24),
        _ => None,
    }
}

fn filetime_tick_duration(ticks: u64) -> Duration {
    Duration::new(
        ticks / WINDOWS_TICKS_PER_SECOND,
        ((ticks % WINDOWS_TICKS_PER_SECOND) * 100) as u32,
    )
}

fn kerberos_etype_for_checksum_type(signature_type: u32) -> Option<KerberosEtype> {
    KerberosEtype::from_checksum_type_id(signature_type.try_into().ok()?)
}

fn ntlm_supplemental_flag_set(flags: u32, flag: u32) -> bool {
    let byte = (flag / 8) as usize;
    let bit = 7 - (flag - 8 * byte as u32);
    flags.to_le_bytes()[byte] & (1 << bit) != 0
}

fn checked_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    target: &'static str,
) -> Result<&'a [u8], Error> {
    let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    if end > bytes.len() {
        return Err(Error::OutOfBounds {
            target,
            offset,
            len,
            total_len: bytes.len(),
        });
    }
    Ok(&bytes[offset..end])
}

fn utf16le_bytes_to_string(bytes: &[u8], target: &'static str) -> Result<String, Error> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidUtf16Length {
            target,
            bytes: bytes.len(),
        });
    }

    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_filetime(&mut self) -> Result<FileTime, Error> {
        Ok(FileTime::from_ticks(self.read_u64()?))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: len,
                remaining: self.remaining(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn align(&mut self, alignment: usize) -> Result<(), Error> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(Error::InvalidAlignment(alignment));
        }
        let aligned = (self.offset + alignment - 1) & !(alignment - 1);
        if aligned > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: aligned - self.offset,
                remaining: self.remaining(),
            });
        }
        self.offset = aligned;
        Ok(())
    }
}

/// PAC parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Input was too short.
    #[error("{target} is too short: expected at least {minimum} bytes, got {actual}")]
    TooShort {
        /// Parsed target.
        target: &'static str,
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// A read exceeded the input length.
    #[error("PAC data is truncated at offset {offset}; need {needed} bytes, have {remaining}")]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },

    /// A length or offset overflowed the target integer type.
    #[error("PAC length overflow")]
    LengthOverflow,

    /// A PAC buffer offset was not aligned to eight bytes.
    #[error("PAC buffer {ul_type} offset {offset} is not eight-byte aligned")]
    BufferOffsetNotAligned {
        /// PAC buffer type.
        ul_type: u32,
        /// PAC buffer offset.
        offset: u64,
    },

    /// A PAC buffer range exceeded the PAC byte length.
    #[error(
        "PAC buffer {ul_type} at offset {offset} with length {len} exceeds PAC length {total_len}"
    )]
    BufferOutOfBounds {
        /// PAC buffer type.
        ul_type: u32,
        /// PAC buffer offset.
        offset: u64,
        /// PAC buffer length.
        len: u32,
        /// PAC byte length.
        total_len: usize,
    },

    /// A sub-structure range exceeded its buffer length.
    #[error(
        "{target} range at offset {offset} with length {len} exceeds buffer length {total_len}"
    )]
    OutOfBounds {
        /// Parsed target.
        target: &'static str,
        /// Offset.
        offset: usize,
        /// Length.
        len: usize,
        /// Total buffer length.
        total_len: usize,
    },

    /// A checksum type is recognized neither for parsing nor verification.
    #[error("unsupported PAC checksum type: {0}")]
    UnsupportedChecksumType(u32),

    /// An encryption type is not supported for PAC credential decryption.
    #[error("unsupported PAC encryption type: {0}")]
    UnsupportedEncryptionType(i32),

    /// A claims compression format is not supported.
    #[error("unsupported PAC claims compression format: {0}")]
    UnsupportedClaimsCompressionFormat(u16),

    /// PAC claims decompression failed.
    #[error("PAC claims decompression failed for format {compression_format}: {message}")]
    ClaimsDecompression {
        /// Claims compression format.
        compression_format: u16,
        /// Decompression error message.
        message: String,
    },

    /// PAC claims decompressed to a length other than the metadata declared.
    #[error(
        "PAC claims decompressed size mismatch for format {compression_format}: expected {expected}, got {actual}"
    )]
    ClaimsDecompressedSizeMismatch {
        /// Claims compression format.
        compression_format: u16,
        /// Expected decompressed byte length.
        expected: usize,
        /// Actual decompressed byte length.
        actual: usize,
    },

    /// A claims value type is not supported.
    #[error("unsupported PAC claim type: {0}")]
    UnsupportedClaimType(u16),

    /// A claim union discriminant did not match the entry type.
    #[error("invalid PAC claim union tag: claim type {claim_type}, union tag {union_tag}")]
    InvalidClaimUnionTag {
        /// Claim type field.
        claim_type: u16,
        /// Union tag field.
        union_tag: u16,
    },

    /// A required PAC buffer was absent.
    #[error("PAC Info Buffers do not contain required {0}")]
    MissingRequiredBuffer(&'static str),

    /// PAC credentials info version was not zero.
    #[error("invalid PAC credentials info version: {0}")]
    InvalidCredentialsInfoVersion(u32),

    /// PAC credentials were decrypted with the wrong key type.
    #[error("PAC credentials key type mismatch: expected {expected}, got {actual}")]
    CredentialKeyTypeMismatch {
        /// Required Kerberos encryption type.
        expected: i32,
        /// Provided Kerberos encryption type.
        actual: i32,
    },

    /// NTLM supplemental credential version was not zero.
    #[error("invalid NTLM supplemental credential version: {0}")]
    InvalidNtlmSupplementalCredentialVersion(u32),

    /// The PAC server checksum did not verify.
    #[error("PAC service checksum verification failed")]
    ServerChecksumVerificationFailed,

    /// PAC authorization data failed DER decoding.
    #[cfg(feature = "messages")]
    #[error("PAC authorization-data DER decode failed: {0}")]
    DerDecode(String),

    /// The NDR wrapper was not little-endian NDR64-compatible data.
    #[error("invalid NDR header")]
    InvalidNdrHeader,

    /// The NDR wrapper object length exceeded the available bytes.
    #[error("invalid NDR object length {object_len}; only {remaining} bytes remain")]
    InvalidNdrObjectLength {
        /// Declared object length.
        object_len: usize,
        /// Remaining bytes.
        remaining: usize,
    },

    /// An NDR pointer was null where the pointed value was required.
    #[error("missing NDR pointer for {0}")]
    MissingNdrPointer(&'static str),

    /// An NDR count was too large to allocate safely.
    #[error("unreasonable NDR count for {target}: {count}")]
    UnreasonableNdrCount {
        /// Parsed target.
        target: &'static str,
        /// Count value.
        count: u32,
    },

    /// An NDR conformant/varying array described invalid bounds.
    #[error(
        "invalid NDR array bounds for {target}: max={max_count}, offset={offset}, actual={actual_count}"
    )]
    InvalidNdrArrayBounds {
        /// Parsed target.
        target: &'static str,
        /// Maximum element count.
        max_count: u32,
        /// Varying array offset.
        offset: u32,
        /// Actual element count.
        actual_count: u32,
    },

    /// A declared count did not match the transmitted conformant array count.
    #[error("NDR count mismatch for {target}: expected {expected}, got {actual}")]
    CountMismatch {
        /// Parsed target.
        target: &'static str,
        /// Expected count.
        expected: u32,
        /// Actual count.
        actual: u32,
    },

    /// RPC Unicode string length metadata was inconsistent.
    #[error(
        "invalid RPC_UNICODE_STRING for {target}: length {length}, maximum length {maximum_length}"
    )]
    InvalidRpcUnicodeString {
        /// Parsed target.
        target: &'static str,
        /// String length in bytes.
        length: u16,
        /// Maximum string length in bytes.
        maximum_length: u16,
    },

    /// RPC Unicode string data did not contain the declared number of UTF-16 units.
    #[error(
        "invalid RPC_UNICODE_STRING data for {target}: expected {expected_units} UTF-16 units, got {actual_units}"
    )]
    InvalidRpcUnicodeStringData {
        /// Parsed target.
        target: &'static str,
        /// Expected UTF-16 units.
        expected_units: usize,
        /// Actual UTF-16 units.
        actual_units: usize,
    },

    /// UTF-16 input had an odd byte length.
    #[error("invalid UTF-16LE length for {target}: {bytes} bytes")]
    InvalidUtf16Length {
        /// Parsed target.
        target: &'static str,
        /// Byte count.
        bytes: usize,
    },

    /// UTF-16 decoding failed.
    #[error("invalid UTF-16LE data for {target}: {message}")]
    InvalidUtf16 {
        /// Parsed target.
        target: &'static str,
        /// Decode error message.
        message: String,
    },

    /// SID revision was unsupported.
    #[error("unsupported SID revision: {0}")]
    InvalidSidRevision(u8),

    /// SID sub-authority count was inconsistent.
    #[error("invalid SID sub-authority count for {target}: max={max_count}, actual={actual_count}")]
    InvalidSidSubAuthorityCount {
        /// Parsed target.
        target: &'static str,
        /// Maximum transmitted sub-authority count.
        max_count: u32,
        /// Actual SID sub-authority count.
        actual_count: u8,
    },

    /// NDR data remained after all KERB_VALIDATION_INFO fields were parsed.
    #[error("trailing NDR bytes after KERB_VALIDATION_INFO: {remaining}")]
    TrailingNdrBytes {
        /// Remaining byte count.
        remaining: usize,
    },

    /// NDR data remained after all fields were parsed.
    #[error("trailing NDR bytes after {target}: {remaining}")]
    TrailingNdrBytesAfter {
        /// Parsed target.
        target: &'static str,
        /// Remaining byte count.
        remaining: usize,
    },

    /// Internal alignment request was invalid.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(usize),

    /// Kerberos cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
}
