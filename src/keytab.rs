//! Kerberos keytab parsing and serialization.
//!
//! This module covers the MIT keytab file format surface needed before client
//! and service flows can consume long-term keys.

use crate::crypto::KerberosEtype;
use crate::file_name;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

const KEYTAB_FIRST_BYTE: u8 = 5;
const KRB5_KTNAME_ENV: &str = "KRB5_KTNAME";

/// Parsed keytab file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Keytab {
    version: u8,
    entries: Vec<Entry>,
}

impl Keytab {
    /// Create an empty version 2 keytab.
    pub fn new() -> Self {
        Self {
            version: 2,
            entries: Vec::new(),
        }
    }

    /// Load and parse a keytab file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = std::fs::read(path.as_ref())?;
        Self::parse(&bytes)
    }

    /// Load and parse the file keytab named by `KRB5_KTNAME`.
    ///
    /// Only file-backed keytab names are supported: bare paths, `FILE:path`,
    /// and `WRFILE:path`. Collection and platform stores such as `DIR:`,
    /// `KEYRING:`, and `MEMORY:` are rejected explicitly.
    pub fn load_from_env() -> Result<Self, Error> {
        let name = std::env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        Self::load_name(name)
    }

    /// Load and parse a keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    pub fn load_name(name: impl AsRef<str>) -> Result<Self, Error> {
        Self::load(Self::file_path_from_keytab_name(name.as_ref())?)
    }

    /// Parse keytab bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::TooShort {
                actual: bytes.len(),
            });
        }
        if bytes[0] != KEYTAB_FIRST_BYTE {
            return Err(Error::InvalidFirstByte(bytes[0]));
        }
        let version = bytes[1];
        if version != 1 && version != 2 {
            return Err(Error::InvalidVersion(version));
        }

        let endian = Endian::for_version(version);
        let mut offset = 2;
        let mut entries = Vec::new();

        while bytes.len().saturating_sub(offset) >= 4 {
            let entry_len = read_i32(bytes, &mut offset, endian)?;
            if entry_len == 0 {
                break;
            }
            if entry_len < 0 {
                let skip = entry_len
                    .checked_abs()
                    .ok_or(Error::LengthOverflow)?
                    .try_into()
                    .map_err(|_| Error::LengthOverflow)?;
                checked_advance(bytes, &mut offset, skip)?;
                continue;
            }

            let entry_len: usize = entry_len.try_into().map_err(|_| Error::LengthOverflow)?;
            let end = checked_end(bytes, offset, entry_len)?;
            let mut entry_offset = 0;
            let entry_bytes = &bytes[offset..end];
            offset = end;

            let principal = Principal::parse(entry_bytes, &mut entry_offset, version, endian)?;
            let timestamp = read_u32(entry_bytes, &mut entry_offset, endian)?;
            let kvno8 = read_u8(entry_bytes, &mut entry_offset)?;
            let etype = read_i16(entry_bytes, &mut entry_offset, endian)? as i32;
            let key_len = read_i16(entry_bytes, &mut entry_offset, endian)?;
            if key_len < 0 {
                return Err(Error::NegativeLength(key_len.into()));
            }
            let key_value = read_bytes(entry_bytes, &mut entry_offset, key_len as usize)?.to_vec();

            let mut kvno = if entry_bytes.len().saturating_sub(entry_offset) >= 4 {
                read_u32(entry_bytes, &mut entry_offset, endian)?
            } else {
                kvno8.into()
            };
            if kvno == 0 {
                kvno = kvno8.into();
            }

            entries.push(Entry {
                principal,
                timestamp,
                kvno8,
                key: EncryptionKey {
                    etype,
                    value: key_value,
                },
                kvno,
            });
        }

        Ok(Self { version, entries })
    }

    /// Save this keytab to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        std::fs::write(path.as_ref(), self.to_bytes()?)?;
        Ok(())
    }

    /// Save this keytab to the file keytab named by `KRB5_KTNAME`.
    pub fn save_to_env(&self) -> Result<(), Error> {
        let name = std::env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        self.save_name(name)
    }

    /// Save this keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    pub fn save_name(&self, name: impl AsRef<str>) -> Result<(), Error> {
        self.save(Self::file_path_from_keytab_name(name.as_ref())?)
    }

    /// Resolve a MIT-style keytab name to a file path.
    ///
    /// This does not touch the filesystem; it only validates that the name
    /// denotes a keytab format backed by this module.
    pub fn file_path_from_keytab_name(name: &str) -> Result<PathBuf, Error> {
        file_name::file_path_from_name(name, &["FILE", "WRFILE"]).map_err(|error| match error {
            file_name::Error::Empty => Error::InvalidKeytabName,
            file_name::Error::UnsupportedType { name_type } => Error::UnsupportedKeytabType {
                keytab_type: name_type,
            },
        })
    }

    /// Serialize the keytab to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let endian = Endian::for_version(self.version);
        let mut out = vec![KEYTAB_FIRST_BYTE, self.version];
        for entry in &self.entries {
            let mut body = Vec::new();
            entry.principal.write_to(&mut body, self.version, endian)?;
            write_u32(&mut body, entry.timestamp, endian);
            body.push(entry.kvno8);
            write_u16_checked(&mut body, entry.key.etype, endian)?;
            write_u16_checked(&mut body, entry.key.value.len(), endian)?;
            body.extend_from_slice(&entry.key.value);
            write_u32(&mut body, entry.kvno, endian);

            let body_len: i32 = body.len().try_into().map_err(|_| Error::LengthOverflow)?;
            write_i32(&mut out, body_len, endian);
            out.extend_from_slice(&body);
        }
        Ok(out)
    }

    /// Keytab file format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Parsed entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Mutable parsed entries, useful for tests and construction.
    pub fn entries_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.entries
    }

    /// Redacted entry metadata, suitable for diagnostics and JSON rendering.
    #[cfg(feature = "serde")]
    pub fn entry_metadata(&self) -> Vec<KeytabEntryMetadata> {
        self.entries
            .iter()
            .map(KeytabEntryMetadata::from_entry)
            .collect()
    }

    /// Return redacted entry metadata as pretty-printed JSON.
    ///
    /// Raw key bytes are intentionally omitted.
    #[cfg(feature = "serde")]
    pub fn entries_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entry_metadata())
    }

    /// Add an entry by deriving key material from a password.
    ///
    /// This mirrors gokrb5's keytab entry generation: the default Kerberos
    /// password salt is `realm + principal components`, and the selected
    /// encryption type's default string-to-key parameters are used.
    pub fn add_entry_from_password(
        &mut self,
        principal: Principal,
        password: impl AsRef<[u8]>,
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error> {
        let etype_impl =
            KerberosEtype::from_etype_id(etype).ok_or(Error::UnsupportedEtype(etype))?;
        let salt = principal.default_password_salt();
        let key = etype_impl.string_to_key(
            password.as_ref(),
            salt.as_bytes(),
            etype_impl.default_s2kparams(),
        )?;
        let timestamp = system_time_to_u32_seconds(timestamp)?;
        self.entries.push(Entry {
            principal,
            timestamp,
            kvno8: kvno,
            key: EncryptionKey { etype, value: key },
            kvno: kvno.into(),
        });
        Ok(())
    }

    /// Find the newest key matching principal components, realm, kvno, and
    /// encryption type. A `kvno` of `0` matches any kvno, mirroring gokrb5.
    pub fn find_key(
        &self,
        principal_components: &[&str],
        realm: &str,
        kvno: u32,
        etype: i32,
    ) -> Result<(&EncryptionKey, u32), Error> {
        let mut selected: Option<&Entry> = None;
        for entry in &self.entries {
            if entry.principal.realm == realm
                && entry.principal.components.len() == principal_components.len()
                && entry
                    .principal
                    .components
                    .iter()
                    .zip(principal_components)
                    .all(|(left, right)| left == right)
                && entry.key.etype == etype
                && (kvno == 0 || entry.kvno == kvno)
            {
                match selected {
                    Some(current) if current.timestamp >= entry.timestamp => {}
                    _ => selected = Some(entry),
                }
            }
        }

        selected
            .map(|entry| (&entry.key, entry.kvno))
            .ok_or_else(|| Error::NoMatchingKey {
                principal: principal_components.join("/"),
                realm: realm.to_owned(),
                kvno,
                etype,
            })
    }
}

impl Default for Keytab {
    fn default() -> Self {
        Self::new()
    }
}

/// A keytab entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Principal for the key.
    pub principal: Principal,
    /// POSIX timestamp in seconds.
    pub timestamp: u32,
    /// 8-bit key version number stored in the fixed entry fields.
    pub kvno8: u8,
    /// Long-term key material.
    pub key: EncryptionKey,
    /// 32-bit key version number, falling back to `kvno8` when absent or zero.
    pub kvno: u32,
}

impl Entry {
    /// Entry timestamp as `SystemTime`.
    pub fn system_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.timestamp.into())
    }
}

/// Keytab principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type. Version 1 keytabs omit this and parse as `0`.
    pub name_type: i32,
}

impl Principal {
    /// Create a keytab principal.
    pub fn new<I, S>(realm: impl Into<String>, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            realm: realm.into(),
            components: components.into_iter().map(Into::into).collect(),
            name_type,
        }
    }

    /// Return the default Kerberos password salt for this principal.
    pub fn default_password_salt(&self) -> String {
        let mut salt = self.realm.clone();
        for component in &self.components {
            salt.push_str(component);
        }
        salt
    }

    /// Principal components joined by `/`.
    pub fn name_string(&self) -> String {
        self.components.join("/")
    }

    /// Principal as `name@REALM`.
    pub fn principal_string(&self) -> String {
        format!("{}@{}", self.name_string(), self.realm)
    }

    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let mut component_count = read_i16(bytes, offset, endian)?;
        if version == 1 {
            component_count = component_count
                .checked_sub(1)
                .ok_or(Error::LengthOverflow)?;
        }
        if component_count < 0 {
            return Err(Error::NegativeLength(component_count.into()));
        }

        let realm = read_counted_string(bytes, offset, endian)?;
        let mut components = Vec::with_capacity(component_count as usize);
        for _ in 0..component_count {
            components.push(read_counted_string(bytes, offset, endian)?);
        }

        let name_type = if version == 1 {
            0
        } else {
            read_i32(bytes, offset, endian)?
        };

        Ok(Self {
            realm,
            components,
            name_type,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        let component_count = if version == 1 {
            self.components
                .len()
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?
        } else {
            self.components.len()
        };
        write_u16_checked(out, component_count, endian)?;
        write_counted_string(out, &self.realm, endian)?;
        for component in &self.components {
            write_counted_string(out, component, endian)?;
        }
        if version != 1 {
            write_i32(out, self.name_type, endian);
        }
        Ok(())
    }
}

/// Kerberos encryption key as stored in a keytab.
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct EncryptionKey {
    /// Kerberos encryption type id.
    pub etype: i32,
    /// Raw key bytes.
    pub value: Vec<u8>,
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("etype", &self.etype)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Redacted keytab entry metadata.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeytabEntryMetadata {
    /// Principal as `name@REALM`.
    pub principal: String,
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type.
    pub name_type: i32,
    /// Entry timestamp as POSIX seconds.
    pub timestamp: u32,
    /// 8-bit key version number.
    #[serde(rename = "KVNO8")]
    pub kvno8: u8,
    /// 32-bit key version number.
    #[serde(rename = "KVNO")]
    pub kvno: u32,
    /// Kerberos encryption type id.
    #[serde(rename = "EType")]
    pub etype: i32,
    /// Length of the key value in bytes.
    pub key_length: usize,
}

#[cfg(feature = "serde")]
impl KeytabEntryMetadata {
    fn from_entry(entry: &Entry) -> Self {
        Self {
            principal: entry.principal.principal_string(),
            realm: entry.principal.realm.clone(),
            components: entry.principal.components.clone(),
            name_type: entry.principal.name_type,
            timestamp: entry.timestamp,
            kvno8: entry.kvno8,
            kvno: entry.kvno,
            etype: entry.key.etype,
            key_length: entry.key.value.len(),
        }
    }
}

/// Keytab parsing and serialization error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File loading or saving failed.
    #[error("keytab file could not be read or written: {0}")]
    Io(#[from] std::io::Error),
    /// The default keytab name could not be read from `KRB5_KTNAME`.
    #[error("default keytab name could not be read from KRB5_KTNAME: {0}")]
    DefaultKeytabName(std::env::VarError),
    /// A keytab name was empty or did not include a path.
    #[error("invalid keytab name")]
    InvalidKeytabName,
    /// The keytab name uses a keytab type this module cannot parse.
    #[error("unsupported keytab type: {keytab_type}")]
    UnsupportedKeytabType {
        /// Keytab type prefix before the first colon.
        keytab_type: String,
    },
    /// Input is too short to contain the keytab header.
    #[error("keytab is too short: {actual} bytes")]
    TooShort {
        /// Actual input length.
        actual: usize,
    },
    /// Keytab does not start with the required first byte.
    #[error("invalid keytab first byte: {0}")]
    InvalidFirstByte(u8),
    /// Unsupported keytab version.
    #[error("invalid keytab version: {0}")]
    InvalidVersion(u8),
    /// A read would exceed the input length.
    #[error("keytab data is truncated at offset {offset}; need {needed} bytes, have {remaining}")]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A signed length was negative where the field cannot be negative.
    #[error("negative keytab length: {0}")]
    NegativeLength(i32),
    /// A length cannot fit in the target integer type.
    #[error("keytab length overflow")]
    LengthOverflow,
    /// A keytab entry timestamp was before the Unix epoch.
    #[error("keytab timestamp is before the Unix epoch: {0}")]
    TimestampBeforeUnixEpoch(#[from] SystemTimeError),
    /// A keytab entry timestamp cannot fit in the file format.
    #[error("keytab timestamp overflow")]
    TimestampOverflow,
    /// Principal strings must be valid UTF-8.
    #[error("invalid keytab string: {0}")]
    InvalidString(#[from] std::str::Utf8Error),
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// Key derivation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),
    /// Key lookup did not find a matching entry.
    #[error("matching key not found in keytab for {principal}@{realm}, kvno {kvno}, etype {etype}")]
    NoMatchingKey {
        /// Principal components joined by `/`.
        principal: String,
        /// Principal realm.
        realm: String,
        /// Requested kvno, or 0 for latest.
        kvno: u32,
        /// Requested encryption type.
        etype: i32,
    },
}

#[derive(Clone, Copy, Debug)]
enum Endian {
    Big,
    Little,
}

impl Endian {
    fn for_version(version: u8) -> Self {
        if version == 1 && cfg!(target_endian = "little") {
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

fn system_time_to_u32_seconds(value: SystemTime) -> Result<u32, Error> {
    value
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()
        .map_err(|_| Error::TimestampOverflow)
}

fn checked_advance(bytes: &[u8], offset: &mut usize, len: usize) -> Result<(), Error> {
    *offset = checked_end(bytes, *offset, len)?;
    Ok(())
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

fn read_counted_string(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<String, Error> {
    let len = read_i16(bytes, offset, endian)?;
    if len < 0 {
        return Err(Error::NegativeLength(len.into()));
    }
    let raw = read_bytes(bytes, offset, len as usize)?;
    Ok(std::str::from_utf8(raw)?.to_owned())
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

fn write_u16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<u16>,
{
    let value = value.try_into().map_err(|_| Error::LengthOverflow)?;
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
    Ok(())
}

fn write_counted_string(out: &mut Vec<u8>, value: &str, endian: Endian) -> Result<(), Error> {
    write_u16_checked(out, value.len(), endian)?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
