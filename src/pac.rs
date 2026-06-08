//! Microsoft Privilege Attribute Certificate (PAC) parsing.
//!
//! This module covers the PAC surface that gokrb5 consumes on the service
//! path: the PAC container, KERB_VALIDATION_INFO, client information,
//! UPN/DNS information, PAC signatures, and AES server checksum verification.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{self, AesEtype};
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

const PAC_HEADER_LEN: usize = 8;
const PAC_INFO_BUFFER_LEN: usize = 16;
const PAC_SERVER_CHECKSUM_KEY_USAGE: u32 = 17;
const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_SECONDS: u64 = 11_644_473_600;
const MAX_REASONABLE_NDR_COUNT: u32 = 1_000_000;

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
    /// Parsed client info, if present and processed.
    pub client_info: Option<ClientInfo>,
    /// Parsed UPN/DNS info, if present and processed.
    pub upn_dns_info: Option<UpnDnsInfo>,
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
            client_info: None,
            upn_dns_info: None,
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
                INFO_TYPE_PAC_CLIENT_INFO if self.client_info.is_none() => {
                    self.client_info = Some(ClientInfo::parse(bytes)?);
                }
                INFO_TYPE_UPN_DNS_INFO if self.upn_dns_info.is_none() => {
                    self.upn_dns_info = Some(UpnDnsInfo::parse(bytes)?);
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
        let etype = aes_etype_for_checksum_type(checksum.signature_type)
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
        read_ndr_wrapper(&mut reader)?;

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

fn read_ndr_wrapper(reader: &mut Reader<'_>) -> Result<(), Error> {
    let target = "NDR KERB_VALIDATION_INFO wrapper";
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
        return Err(Error::MissingNdrPointer("KERB_VALIDATION_INFO"));
    }
    Ok(())
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

fn aes_etype_for_checksum_type(signature_type: u32) -> Option<AesEtype> {
    AesEtype::from_checksum_type_id(signature_type.try_into().ok()?)
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

    /// A required PAC buffer was absent.
    #[error("PAC Info Buffers do not contain required {0}")]
    MissingRequiredBuffer(&'static str),

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

    /// Internal alignment request was invalid.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(usize),

    /// Kerberos cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
}
