//! MIT credential cache parsing and serialization.
//!
//! This module handles the file credential cache format surface needed before
//! client flows can persist and reload KDC-issued credentials. Ticket bodies
//! remain opaque DER bytes until the crypto and ASN.1 message layers are wired
//! together.

use std::path::Path;

const CCACHE_FIRST_BYTE: u8 = 5;
const HEADER_FIELD_TAG_KDC_OFFSET: u16 = 1;

/// Parsed MIT credential cache file.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct CCache {
    version: u8,
    header: Header,
    default_principal: Principal,
    credentials: Vec<Credential>,
}

impl CCache {
    /// Create an empty version 4 credential cache.
    pub fn new(default_principal: Principal) -> Self {
        Self {
            version: 4,
            header: Header::default(),
            default_principal,
            credentials: Vec::new(),
        }
    }

    /// Load and parse a credential cache file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = std::fs::read(path.as_ref())?;
        Self::parse(&bytes)
    }

    /// Save this credential cache to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        std::fs::write(path.as_ref(), self.to_bytes()?)?;
        Ok(())
    }

    /// Parse credential cache bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::TooShort {
                actual: bytes.len(),
            });
        }
        if bytes[0] != CCACHE_FIRST_BYTE {
            return Err(Error::InvalidFirstByte(bytes[0]));
        }

        let version = bytes[1];
        if !(1..=4).contains(&version) {
            return Err(Error::InvalidVersion(version));
        }

        let endian = Endian::for_version(version);
        let mut offset = 2;
        let header = if version == 4 {
            Header::parse(bytes, &mut offset, endian)?
        } else {
            Header::default()
        };
        let default_principal = Principal::parse(bytes, &mut offset, version, endian)?;
        let mut credentials = Vec::new();

        while offset < bytes.len() {
            credentials.push(Credential::parse(bytes, &mut offset, version, endian)?);
        }

        Ok(Self {
            version,
            header,
            default_principal,
            credentials,
        })
    }

    /// Serialize the credential cache to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let endian = Endian::for_version(self.version);
        let mut out = vec![CCACHE_FIRST_BYTE, self.version];
        if self.version == 4 {
            self.header.write_to(&mut out, endian)?;
        }
        self.default_principal
            .write_to(&mut out, self.version, endian)?;
        for credential in &self.credentials {
            credential.write_to(&mut out, self.version, endian)?;
        }
        Ok(out)
    }

    /// Credential cache file format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Version 4 header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Mutable version 4 header, useful for construction.
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Default client principal.
    pub fn default_principal(&self) -> &Principal {
        &self.default_principal
    }

    /// Mutable default client principal, useful for construction.
    pub fn default_principal_mut(&mut self) -> &mut Principal {
        &mut self.default_principal
    }

    /// Default client realm.
    pub fn client_realm(&self) -> &str {
        &self.default_principal.realm
    }

    /// Default client principal components joined by `/`.
    pub fn client_name(&self) -> String {
        self.default_principal.name_string()
    }

    /// Parsed credentials, including configuration entries.
    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    /// Mutable parsed credentials, useful for tests and construction.
    pub fn credentials_mut(&mut self) -> &mut Vec<Credential> {
        &mut self.credentials
    }

    /// Insert a credential, replacing an existing credential for the same
    /// exact client and server principals.
    pub fn upsert_credential(&mut self, credential: Credential) -> Option<Credential> {
        if let Some(existing) = self.credentials.iter_mut().find(|existing| {
            existing.client == credential.client && existing.server == credential.server
        }) {
            Some(std::mem::replace(existing, credential))
        } else {
            self.credentials.push(credential);
            None
        }
    }

    /// Remove non-configuration credentials for a client principal.
    ///
    /// X-CACHECONF entries are preserved because they carry cache metadata
    /// rather than Kerberos tickets.
    pub fn remove_entries_for_client(&mut self, client: &Principal) -> Vec<Credential> {
        let mut removed = Vec::new();
        let mut index = 0;
        while index < self.credentials.len() {
            if same_principal_identity(&self.credentials[index].client, client)
                && !self.credentials[index]
                    .server
                    .realm
                    .starts_with("X-CACHECONF")
            {
                removed.push(self.credentials.remove(index));
            } else {
                index += 1;
            }
        }
        removed
    }

    /// Return credentials excluding X-CACHECONF configuration entries.
    pub fn entries(&self) -> Vec<&Credential> {
        self.credentials
            .iter()
            .filter(|credential| !credential.server.realm.starts_with("X-CACHECONF"))
            .collect()
    }

    /// Test whether the cache contains a server principal by name components.
    ///
    /// Like gokrb5, name type and realm are not significant for this check.
    pub fn contains_server(&self, components: &[&str]) -> bool {
        self.get_entry(components).is_some()
    }

    /// Return the first credential matching a server principal by components.
    pub fn get_entry(&self, components: &[&str]) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.server.matches_components(components))
    }
}

fn same_principal_identity(left: &Principal, right: &Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

/// Version 4 ccache header.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Header {
    /// Header fields in file order.
    pub fields: Vec<HeaderField>,
}

impl Header {
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        let length = read_u16(bytes, offset, endian)? as usize;
        let end = checked_end(bytes, *offset, length)?;
        let mut fields = Vec::new();

        while *offset < end {
            let tag = read_u16(bytes, offset, endian)?;
            let field_length = read_u16(bytes, offset, endian)? as usize;
            let value = read_bytes(bytes, offset, field_length)?.to_vec();
            let field = HeaderField { tag, value };
            field.validate()?;
            fields.push(field);
        }

        if *offset != end {
            return Err(Error::InvalidHeaderLength);
        }

        Ok(Self { fields })
    }

    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        let mut body = Vec::new();
        for field in &self.fields {
            field.validate()?;
            write_u16(&mut body, field.tag, endian);
            write_u16_checked(&mut body, field.value.len(), endian)?;
            body.extend_from_slice(&field.value);
        }

        write_u16_checked(out, body.len(), endian)?;
        out.extend_from_slice(&body);
        Ok(())
    }
}

/// One version 4 ccache header field.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct HeaderField {
    /// Field tag.
    pub tag: u16,
    /// Raw field value.
    pub value: Vec<u8>,
}

impl HeaderField {
    fn validate(&self) -> Result<(), Error> {
        if self.tag == HEADER_FIELD_TAG_KDC_OFFSET && self.value.len() != 8 {
            return Err(Error::InvalidHeaderField {
                tag: self.tag,
                length: self.value.len(),
            });
        }
        Ok(())
    }
}

/// Principal stored in a credential cache.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Principal name type.
    pub name_type: i32,
    /// Principal components.
    pub components: Vec<String>,
}

impl Principal {
    /// Create a principal.
    pub fn new(realm: impl Into<String>, name_type: i32, components: Vec<String>) -> Self {
        Self {
            realm: realm.into(),
            name_type,
            components,
        }
    }

    /// Principal components joined by `/`.
    pub fn name_string(&self) -> String {
        self.components.join("/")
    }

    /// Compare principal components, ignoring name type and realm like gokrb5's
    /// `PrincipalName.Equal`.
    pub fn matches_components(&self, components: &[&str]) -> bool {
        self.components.len() == components.len()
            && self
                .components
                .iter()
                .zip(components)
                .all(|(left, right)| left == right)
    }

    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let name_type = if version == 1 {
            0
        } else {
            read_i32(bytes, offset, endian)?
        };

        let mut component_count = read_i32(bytes, offset, endian)?;
        if version == 1 {
            component_count = component_count
                .checked_sub(1)
                .ok_or(Error::LengthOverflow)?;
        }
        if component_count < 0 {
            return Err(Error::NegativeLength(component_count));
        }

        let realm = read_counted_string(bytes, offset, endian)?;
        let mut components = Vec::with_capacity(component_count as usize);
        for _ in 0..component_count {
            components.push(read_counted_string(bytes, offset, endian)?);
        }

        Ok(Self {
            realm,
            name_type,
            components,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        if version != 1 {
            write_i32(out, self.name_type, endian);
        }

        let component_count = if version == 1 {
            self.components
                .len()
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?
        } else {
            self.components.len()
        };
        write_i32_len_checked(out, component_count, endian)?;
        write_counted_string(out, &self.realm, endian)?;
        for component in &self.components {
            write_counted_string(out, component, endian)?;
        }
        Ok(())
    }
}

/// Credential cache entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Credential {
    /// Client principal.
    pub client: Principal,
    /// Server principal.
    pub server: Principal,
    /// Session key.
    pub key: EncryptionKey,
    /// Credential timestamps as POSIX seconds.
    pub times: CredentialTimes,
    /// Whether the ticket is encrypted in the session key.
    pub is_skey: bool,
    /// Kerberos ticket flags as the raw four bytes stored in ccache.
    pub ticket_flags: [u8; 4],
    /// Client addresses.
    pub addresses: Vec<HostAddress>,
    /// Authorization data entries.
    pub auth_data: Vec<AuthorizationDataEntry>,
    /// Primary ticket DER bytes.
    pub ticket: Vec<u8>,
    /// Second ticket DER bytes.
    pub second_ticket: Vec<u8>,
}

impl Credential {
    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let client = Principal::parse(bytes, offset, version, endian)?;
        let server = Principal::parse(bytes, offset, version, endian)?;

        let mut etype = read_i16(bytes, offset, endian)? as i32;
        if version == 3 {
            etype = read_i16(bytes, offset, endian)? as i32;
        }
        let key = EncryptionKey {
            etype,
            value: read_data(bytes, offset, endian)?,
        };

        let times = CredentialTimes {
            auth_time: read_u32(bytes, offset, endian)?,
            start_time: read_u32(bytes, offset, endian)?,
            end_time: read_u32(bytes, offset, endian)?,
            renew_till: read_u32(bytes, offset, endian)?,
        };
        let is_skey = read_u8(bytes, offset)? != 0;
        let ticket_flags = read_bytes(bytes, offset, 4)?
            .try_into()
            .map_err(|_| Error::LengthOverflow)?;

        let address_count = read_count(bytes, offset, endian)?;
        let mut addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            addresses.push(HostAddress::parse(bytes, offset, endian)?);
        }

        let auth_data_count = read_count(bytes, offset, endian)?;
        let mut auth_data = Vec::with_capacity(auth_data_count);
        for _ in 0..auth_data_count {
            auth_data.push(AuthorizationDataEntry::parse(bytes, offset, endian)?);
        }

        let ticket = read_data(bytes, offset, endian)?;
        let second_ticket = read_data(bytes, offset, endian)?;

        Ok(Self {
            client,
            server,
            key,
            times,
            is_skey,
            ticket_flags,
            addresses,
            auth_data,
            ticket,
            second_ticket,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        self.client.write_to(out, version, endian)?;
        self.server.write_to(out, version, endian)?;
        write_i16_checked(out, self.key.etype, endian)?;
        if version == 3 {
            write_i16_checked(out, self.key.etype, endian)?;
        }
        write_data(out, &self.key.value, endian)?;
        write_u32(out, self.times.auth_time, endian);
        write_u32(out, self.times.start_time, endian);
        write_u32(out, self.times.end_time, endian);
        write_u32(out, self.times.renew_till, endian);
        out.push(u8::from(self.is_skey));
        out.extend_from_slice(&self.ticket_flags);

        write_i32_len_checked(out, self.addresses.len(), endian)?;
        for address in &self.addresses {
            address.write_to(out, endian)?;
        }

        write_i32_len_checked(out, self.auth_data.len(), endian)?;
        for entry in &self.auth_data {
            entry.write_to(out, endian)?;
        }

        write_data(out, &self.ticket, endian)?;
        write_data(out, &self.second_ticket, endian)?;
        Ok(())
    }
}

/// Kerberos encryption key stored in a ccache credential.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct EncryptionKey {
    /// Kerberos encryption type id.
    pub etype: i32,
    /// Raw key bytes.
    pub value: Vec<u8>,
}

/// Credential timestamp fields as POSIX seconds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct CredentialTimes {
    /// Initial authentication time.
    pub auth_time: u32,
    /// Ticket start time.
    pub start_time: u32,
    /// Ticket expiration time.
    pub end_time: u32,
    /// Renewable-until time.
    pub renew_till: u32,
}

/// Host address stored in a ccache credential.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct HostAddress {
    /// Kerberos address type id.
    pub addr_type: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

impl HostAddress {
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        Ok(Self {
            addr_type: read_i16(bytes, offset, endian)? as i32,
            address: read_data(bytes, offset, endian)?,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        write_i16_checked(out, self.addr_type, endian)?;
        write_data(out, &self.address, endian)
    }
}

/// Authorization data entry stored in a ccache credential.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct AuthorizationDataEntry {
    /// Authorization data type id.
    pub ad_type: i32,
    /// Raw authorization data bytes.
    pub data: Vec<u8>,
}

impl AuthorizationDataEntry {
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        Ok(Self {
            ad_type: read_i16(bytes, offset, endian)? as i32,
            data: read_data(bytes, offset, endian)?,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        write_i16_checked(out, self.ad_type, endian)?;
        write_data(out, &self.data, endian)
    }
}

/// Credential cache parsing and serialization error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File loading failed.
    #[error("credential cache file could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// Input is too short to contain the ccache header.
    #[error("credential cache is too short: {actual} bytes")]
    TooShort {
        /// Actual input length.
        actual: usize,
    },
    /// CCache does not start with the required first byte.
    #[error("invalid credential cache first byte: {0}")]
    InvalidFirstByte(u8),
    /// Unsupported ccache version.
    #[error("invalid credential cache version: {0}")]
    InvalidVersion(u8),
    /// A read would exceed the input length.
    #[error(
        "credential cache data is truncated at offset {offset}; need {needed} bytes, have {remaining}"
    )]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A signed length was negative where the field cannot be negative.
    #[error("negative credential cache length: {0}")]
    NegativeLength(i32),
    /// A length cannot fit in the target integer type.
    #[error("credential cache length overflow")]
    LengthOverflow,
    /// Principal strings must be valid UTF-8.
    #[error("invalid credential cache string: {0}")]
    InvalidString(#[from] std::str::Utf8Error),
    /// A v4 header field is malformed.
    #[error("invalid credential cache header field tag {tag} with length {length}")]
    InvalidHeaderField {
        /// Field tag.
        tag: u16,
        /// Field value length.
        length: usize,
    },
    /// The v4 header length did not match parsed fields.
    #[error("invalid credential cache header length")]
    InvalidHeaderLength,
}

#[derive(Clone, Copy, Debug)]
enum Endian {
    Big,
    Little,
}

impl Endian {
    fn for_version(version: u8) -> Self {
        if (version == 1 || version == 2) && cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
}

fn checked_end(bytes: &[u8], offset: usize, len: usize) -> Result<usize, Error> {
    let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            offset,
            needed: len,
            remaining: bytes.len().saturating_sub(offset),
        });
    }
    Ok(end)
}

fn read_bytes<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], Error> {
    let start = *offset;
    let end = checked_end(bytes, start, len)?;
    *offset = end;
    Ok(&bytes[start..end])
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, Error> {
    Ok(read_bytes(bytes, offset, 1)?[0])
}

fn read_i16(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i16, Error> {
    let raw = read_bytes(bytes, offset, 2)?;
    Ok(match endian {
        Endian::Big => i16::from_be_bytes([raw[0], raw[1]]),
        Endian::Little => i16::from_le_bytes([raw[0], raw[1]]),
    })
}

fn read_u16(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<u16, Error> {
    let raw = read_bytes(bytes, offset, 2)?;
    Ok(match endian {
        Endian::Big => u16::from_be_bytes([raw[0], raw[1]]),
        Endian::Little => u16::from_le_bytes([raw[0], raw[1]]),
    })
}

fn read_i32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i32, Error> {
    let raw = read_bytes(bytes, offset, 4)?;
    Ok(match endian {
        Endian::Big => i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
        Endian::Little => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
    })
}

fn read_u32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<u32, Error> {
    let raw = read_bytes(bytes, offset, 4)?;
    Ok(match endian {
        Endian::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
        Endian::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
    })
}

fn read_count(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<usize, Error> {
    let count = read_i32(bytes, offset, endian)?;
    if count < 0 {
        return Err(Error::NegativeLength(count));
    }
    count.try_into().map_err(|_| Error::LengthOverflow)
}

fn read_data(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Vec<u8>, Error> {
    let len = read_count(bytes, offset, endian)?;
    Ok(read_bytes(bytes, offset, len)?.to_vec())
}

fn read_counted_string(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<String, Error> {
    let raw = read_data(bytes, offset, endian)?;
    Ok(std::str::from_utf8(&raw)?.to_owned())
}

fn write_i32(out: &mut Vec<u8>, value: i32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

fn write_u32(out: &mut Vec<u8>, value: u32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

fn write_u16(out: &mut Vec<u8>, value: u16, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

fn write_i16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<i16>,
{
    let value = value.try_into().map_err(|_| Error::LengthOverflow)?;
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
    Ok(())
}

fn write_u16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<u16>,
{
    let value = value.try_into().map_err(|_| Error::LengthOverflow)?;
    write_u16(out, value, endian);
    Ok(())
}

fn write_i32_len_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<i32>,
{
    let value = value.try_into().map_err(|_| Error::LengthOverflow)?;
    write_i32(out, value, endian);
    Ok(())
}

fn write_data(out: &mut Vec<u8>, value: &[u8], endian: Endian) -> Result<(), Error> {
    write_i32_len_checked(out, value.len(), endian)?;
    out.extend_from_slice(value);
    Ok(())
}

fn write_counted_string(out: &mut Vec<u8>, value: &str, endian: Endian) -> Result<(), Error> {
    write_data(out, value.as_bytes(), endian)
}
