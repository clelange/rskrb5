//! Kerberos `krb5.conf` parsing.
//!
//! This module covers the gokrb5-compatible configuration surface needed by
//! later client and service modules: libdefaults, realm host mappings, domain
//! realm lookup, duration parsing, and configured KDC discovery.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const KRB5_CONFIG_ENV: &str = "KRB5_CONFIG";
#[cfg(target_family = "unix")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/krb5.conf"];
#[cfg(target_family = "windows")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"];
#[cfg(not(any(target_family = "unix", target_family = "windows")))]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &[];

const DEFAULT_ENCTYPES: &[&str] = &[
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "des3-cbc-sha1",
    "arcfour-hmac-md5",
    "camellia256-cts-cmac",
    "camellia128-cts-cmac",
    "des-cbc-crc",
    "des-cbc-md5",
    "des-cbc-md4",
];

const DEFAULT_PREAUTH_TYPES: &[i32] = &[17, 16, 15, 14];

/// Parsed Kerberos configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Config {
    /// `[libdefaults]` values.
    pub libdefaults: LibDefaults,
    /// `[realms]` entries in file order.
    pub realms: Vec<Realm>,
    /// `[domain_realm]` mappings keyed by lower-case domain names.
    pub domain_realm: BTreeMap<String, String>,
}

impl Config {
    /// Create a config with MIT/gokrb5-style defaults and no parsed sections.
    pub fn new() -> Self {
        Self {
            libdefaults: LibDefaults::new(),
            realms: Vec::new(),
            domain_realm: BTreeMap::new(),
        }
    }

    /// Load and parse a `krb5.conf` file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let input = std::fs::read_to_string(path.as_ref())?;
        Self::parse(&input)
    }

    /// Load and parse the `krb5.conf` path list named by `KRB5_CONFIG`.
    ///
    /// The environment value is split with the platform path-list separator.
    /// On Unix this matches the colon-separated list used by MIT Kerberos.
    pub fn load_from_env() -> Result<Self, Error> {
        let value = std::env::var_os(KRB5_CONFIG_ENV).ok_or(Error::DefaultConfigName)?;
        Self::load_paths(std::env::split_paths(&value))
    }

    /// Load the default Kerberos configuration.
    ///
    /// `KRB5_CONFIG` takes precedence when set. Otherwise this tries platform
    /// defaults such as `/etc/krb5.conf` on Unix.
    pub fn load_default() -> Result<Self, Error> {
        if std::env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_paths(PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied())
    }

    /// Load the default Kerberos configuration or parse an embedded fallback.
    ///
    /// The embedded config is used only when no environment or platform
    /// default config source exists. If a configured file exists but cannot be
    /// read or parsed, that error is returned.
    pub fn load_default_or_parse(embedded_krb5_conf: &str) -> Result<Self, Error> {
        if std::env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_or_parse_paths(
            embedded_krb5_conf,
            PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied(),
        )
    }

    /// Load and parse one or more `krb5.conf` files.
    ///
    /// Files are concatenated in iterator order before parsing, preserving the
    /// same section semantics as a single file with repeated sections.
    pub fn load_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut input = String::new();
        let mut loaded = 0usize;
        for path in paths {
            let path = path.as_ref();
            if path.as_os_str().is_empty() {
                continue;
            }
            if loaded > 0 {
                input.push('\n');
            }
            input.push_str(&std::fs::read_to_string(path)?);
            input.push('\n');
            loaded += 1;
        }
        if loaded == 0 {
            return Err(Error::EmptyConfigPathList);
        }
        Self::parse(&input)
    }

    fn load_default_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let paths = existing_default_config_paths(paths);
        if paths.is_empty() {
            return Err(Error::NoDefaultConfig);
        }
        Self::load_paths(paths)
    }

    fn load_default_or_parse_paths<I, P>(embedded_krb5_conf: &str, paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        match Self::load_default_paths(paths) {
            Ok(config) => Ok(config),
            Err(Error::NoDefaultConfig) => Self::parse(embedded_krb5_conf),
            Err(error) => Err(error),
        }
    }

    /// Parse a `krb5.conf` string.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut config = Self::new();
        let mut current = SectionKind::Unknown;
        let mut lines = Vec::new();

        for (index, raw) in input.lines().enumerate() {
            let line_number = index + 1;
            let cleaned = strip_comments(raw).trim();
            if cleaned.is_empty() {
                continue;
            }

            if let Some(section) = SectionKind::parse(cleaned) {
                apply_section(&mut config, current, &lines)?;
                current = section;
                lines.clear();
                continue;
            }

            if current != SectionKind::Unknown {
                lines.push(Line {
                    number: line_number,
                    text: cleaned.to_owned(),
                });
            }
        }

        apply_section(&mut config, current, &lines)?;
        Ok(config)
    }

    /// Render a gokrb5-style JSON snapshot of the parsed configuration.
    #[cfg(feature = "serde")]
    pub fn json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&ConfigJson::from(self))
    }

    /// Return the configured realm with this name.
    pub fn realm(&self, realm: &str) -> Option<&Realm> {
        self.realms.iter().find(|entry| entry.realm == realm)
    }

    /// Resolve a DNS name to a Kerberos realm using `[domain_realm]`.
    ///
    /// This mirrors gokrb5's lookup order: exact hostname first, then the most
    /// specific dotted suffix mapping.
    pub fn resolve_realm(&self, domain_name: &str) -> Option<&str> {
        let domain_name = domain_name.trim_end_matches('.');
        if let Some(realm) = self.domain_realm.get(domain_name) {
            return Some(realm);
        }

        let parts: Vec<_> = domain_name.split('.').collect();
        for start in 1..parts.len() {
            let suffix = format!(".{}", parts[start..].join("."));
            if let Some(realm) = self.domain_realm.get(&suffix) {
                return Some(realm);
            }
        }
        None
    }

    /// Return KDC hosts configured for a realm.
    ///
    /// DNS lookup is intentionally not performed here; the first port keeps
    /// host configuration deterministic and leaves DNS transport for the Tokio
    /// adapter layer.
    pub fn configured_kdcs(&self, realm: &str) -> Result<&[String], Error> {
        let realm_entry = self
            .realm(realm)
            .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
        if realm_entry.kdc.is_empty() {
            return Err(Error::NoKdc(realm.to_owned()));
        }
        Ok(&realm_entry.kdc)
    }

    /// Return password-change servers configured for a realm.
    pub fn configured_kpasswd_servers(&self, realm: &str) -> Result<&[String], Error> {
        let realm_entry = self
            .realm(realm)
            .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
        if realm_entry.kpasswd_server.is_empty() {
            return Err(Error::NoKpasswdServer(realm.to_owned()));
        }
        Ok(&realm_entry.kpasswd_server)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

fn existing_default_config_paths<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .filter(|path| path.is_file())
        .collect()
}

/// `[libdefaults]` configuration values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LibDefaults {
    /// Whether weak crypto names are retained before supported enctype
    /// filtering.
    pub allow_weak_crypto: bool,
    /// Whether clients should request canonicalization.
    pub canonicalize: bool,
    /// Credential cache type.
    pub ccache_type: i32,
    /// Accepted clock skew.
    pub clockskew: Duration,
    /// Default credential cache name.
    pub default_ccache_name: String,
    /// Default client keytab path.
    pub default_client_keytab_name: String,
    /// Default service keytab path.
    pub default_keytab_name: String,
    /// Default realm.
    pub default_realm: String,
    /// Preferred TGS enctype names.
    pub default_tgs_enctypes: Vec<String>,
    /// Preferred ticket enctype names.
    pub default_tkt_enctypes: Vec<String>,
    /// Preferred TGS enctype IDs implemented by gokrb5-compatible crypto.
    pub default_tgs_enctype_ids: Vec<i32>,
    /// Preferred ticket enctype IDs implemented by gokrb5-compatible crypto.
    pub default_tkt_enctype_ids: Vec<i32>,
    /// Whether hostnames should be DNS-canonicalized.
    pub dns_canonicalize_hostname: bool,
    /// Whether KDC DNS lookup is enabled.
    pub dns_lookup_kdc: bool,
    /// Whether realm DNS lookup is enabled.
    pub dns_lookup_realm: bool,
    /// Extra local addresses.
    pub extra_addresses: Vec<IpAddr>,
    /// Whether tickets should be forwardable.
    pub forwardable: bool,
    /// Whether acceptor hostname mismatches are ignored.
    pub ignore_acceptor_hostname: bool,
    /// Whether `.k5login` is authoritative.
    pub k5login_authoritative: bool,
    /// `.k5login` directory.
    pub k5login_directory: String,
    /// KDC default options bit string as a 32-bit integer.
    pub kdc_default_options: u32,
    /// KDC time sync setting.
    pub kdc_time_sync: i32,
    /// Whether addresses should be omitted from tickets.
    pub no_addresses: bool,
    /// Permitted enctype names.
    pub permitted_enctypes: Vec<String>,
    /// Permitted enctype IDs implemented by gokrb5-compatible crypto.
    pub permitted_enctype_ids: Vec<i32>,
    /// Preferred preauthentication type IDs.
    pub preferred_preauth_types: Vec<i32>,
    /// Whether tickets should be proxiable.
    pub proxiable: bool,
    /// Whether reverse DNS is enabled.
    pub rdns: bool,
    /// Realm suffix search setting.
    pub realm_try_domains: i32,
    /// Renewable ticket lifetime.
    pub renew_lifetime: Duration,
    /// Safe checksum type.
    pub safe_checksum_type: i32,
    /// Ticket lifetime.
    pub ticket_lifetime: Duration,
    /// UDP preference limit.
    pub udp_preference_limit: i32,
    /// Whether AP-REQ verification failure should be fatal.
    pub verify_ap_req_nofail: bool,
}

impl LibDefaults {
    /// Create default libdefaults.
    pub fn new() -> Self {
        let default_enctypes = DEFAULT_ENCTYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let default_client_keytab_name = format!(
            "/usr/local/var/krb5/user/{}/client.keytab",
            std::env::var("UID").unwrap_or_else(|_| "0".to_owned())
        );
        let mut defaults = Self {
            allow_weak_crypto: false,
            canonicalize: false,
            ccache_type: 4,
            clockskew: Duration::from_secs(300),
            default_ccache_name: String::new(),
            default_client_keytab_name,
            default_keytab_name: "/etc/krb5.keytab".to_owned(),
            default_realm: String::new(),
            default_tgs_enctypes: default_enctypes.clone(),
            default_tkt_enctypes: default_enctypes.clone(),
            default_tgs_enctype_ids: Vec::new(),
            default_tkt_enctype_ids: Vec::new(),
            dns_canonicalize_hostname: true,
            dns_lookup_kdc: false,
            dns_lookup_realm: false,
            extra_addresses: Vec::new(),
            forwardable: false,
            ignore_acceptor_hostname: false,
            k5login_authoritative: false,
            k5login_directory: std::env::var("HOME").unwrap_or_default(),
            kdc_default_options: 0x0000_0010,
            kdc_time_sync: 1,
            no_addresses: true,
            permitted_enctypes: default_enctypes,
            permitted_enctype_ids: Vec::new(),
            preferred_preauth_types: DEFAULT_PREAUTH_TYPES.to_vec(),
            proxiable: false,
            rdns: true,
            realm_try_domains: -1,
            renew_lifetime: Duration::ZERO,
            safe_checksum_type: 8,
            ticket_lifetime: Duration::from_secs(24 * 60 * 60),
            udp_preference_limit: 1465,
            verify_ap_req_nofail: false,
        };
        defaults.refresh_enctype_ids();
        defaults
    }

    fn parse_lines(&mut self, lines: &[Line]) -> Result<(), Error> {
        for line in lines {
            let (key, value) = parse_assignment(line, "libdefaults")?;
            let key = key.to_ascii_lowercase();
            let key = key.as_str();
            if key.contains("v4_") {
                return Err(Error::UnsupportedDirective(
                    "v4 configurations are not supported".to_owned(),
                ));
            }

            match key {
                "allow_weak_crypto" => self.allow_weak_crypto = parse_boolean(value)?,
                "canonicalize" => self.canonicalize = parse_boolean(value)?,
                "ccache_type" => self.ccache_type = parse_i32(value, line, key)?,
                "clockskew" => self.clockskew = parse_duration(value)?,
                "default_ccache_name" => self.default_ccache_name = value.to_owned(),
                "default_client_keytab_name" => {
                    self.default_client_keytab_name = value.to_owned();
                }
                "default_keytab_name" => self.default_keytab_name = value.to_owned(),
                "default_realm" => self.default_realm = value.to_owned(),
                "default_tgs_enctypes" => self.default_tgs_enctypes = parse_words(value),
                "default_tkt_enctypes" => self.default_tkt_enctypes = parse_words(value),
                "dns_canonicalize_hostname" => {
                    self.dns_canonicalize_hostname = parse_boolean(value)?;
                }
                "dns_lookup_kdc" => self.dns_lookup_kdc = parse_boolean(value)?,
                "dns_lookup_realm" => self.dns_lookup_realm = parse_boolean(value)?,
                "extra_addresses" => self.extra_addresses = parse_ip_addresses(value),
                "forwardable" => self.forwardable = parse_boolean(value)?,
                "ignore_acceptor_hostname" => {
                    self.ignore_acceptor_hostname = parse_boolean(value)?;
                }
                "k5login_authoritative" => {
                    self.k5login_authoritative = parse_boolean(value)?;
                }
                "k5login_directory" => self.k5login_directory = value.to_owned(),
                "kdc_default_options" => {
                    self.kdc_default_options = parse_hex_u32(value, line, key)?
                }
                "kdc_timesync" => self.kdc_time_sync = parse_i32(value, line, key)?,
                "noaddresses" | "no_addresses" => self.no_addresses = parse_boolean(value)?,
                "permitted_enctypes" => self.permitted_enctypes = parse_words(value),
                "preferred_preauth_types" => {
                    self.preferred_preauth_types = parse_i32_list(value, line, key)?;
                }
                "proxiable" => self.proxiable = parse_boolean(value)?,
                "rdns" => self.rdns = parse_boolean(value)?,
                "realm_try_domains" => self.realm_try_domains = parse_i32(value, line, key)?,
                "renew_lifetime" => self.renew_lifetime = parse_duration(value)?,
                "safe_checksum_type" => self.safe_checksum_type = parse_i32(value, line, key)?,
                "ticket_lifetime" => self.ticket_lifetime = parse_duration(value)?,
                "udp_preference_limit" => {
                    self.udp_preference_limit = parse_i32(value, line, key)?;
                }
                "verify_ap_req_nofail" => {
                    self.verify_ap_req_nofail = parse_boolean(value)?;
                }
                _ => {}
            }
        }

        self.refresh_enctype_ids();
        Ok(())
    }

    fn refresh_enctype_ids(&mut self) {
        self.default_tgs_enctype_ids =
            parse_supported_enctype_ids(&self.default_tgs_enctypes, self.allow_weak_crypto);
        self.default_tkt_enctype_ids =
            parse_supported_enctype_ids(&self.default_tkt_enctypes, self.allow_weak_crypto);
        self.permitted_enctype_ids =
            parse_supported_enctype_ids(&self.permitted_enctypes, self.allow_weak_crypto);
    }
}

impl Default for LibDefaults {
    fn default() -> Self {
        Self::new()
    }
}

/// One `[realms]` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Realm {
    /// Realm name.
    pub realm: String,
    /// Administrative server hosts.
    pub admin_server: Vec<String>,
    /// Default DNS domain.
    pub default_domain: String,
    /// KDC hosts.
    pub kdc: Vec<String>,
    /// Password-change server hosts.
    pub kpasswd_server: Vec<String>,
    /// Master KDC hosts.
    pub master_kdc: Vec<String>,
}

impl Realm {
    fn new(realm: String) -> Self {
        Self {
            realm,
            admin_server: Vec::new(),
            default_domain: String::new(),
            kdc: Vec::new(),
            kpasswd_server: Vec::new(),
            master_kdc: Vec::new(),
        }
    }

    fn parse(name: &str, lines: &[Line]) -> Result<Self, Error> {
        let mut realm = Self::new(name.to_owned());
        let mut admin_final = false;
        let mut kdc_final = false;
        let mut kpasswd_final = false;
        let mut master_final = false;

        for line in lines {
            let (key, value) = parse_assignment(line, "realms")?;
            let key = key.to_ascii_lowercase();
            let key = key.as_str();
            if key.contains("v4_") {
                return Err(Error::UnsupportedDirective(
                    "v4 configurations are not supported".to_owned(),
                ));
            }

            match key {
                "admin_server" => {
                    append_until_final(&mut realm.admin_server, value, &mut admin_final);
                }
                "default_domain" => realm.default_domain = value.to_owned(),
                "kdc" => {
                    let value = add_default_port(value, 88);
                    append_until_final(&mut realm.kdc, &value, &mut kdc_final);
                }
                "kpasswd_server" => {
                    append_until_final(&mut realm.kpasswd_server, value, &mut kpasswd_final);
                }
                "master_kdc" => {
                    append_until_final(&mut realm.master_kdc, value, &mut master_final);
                }
                _ => {}
            }
        }

        if realm.kpasswd_server.is_empty() {
            realm.kpasswd_server = realm
                .admin_server
                .iter()
                .map(|admin| {
                    let host = admin.split(':').next().unwrap_or(admin);
                    format!("{host}:464")
                })
                .collect();
        }

        Ok(realm)
    }
}

/// Configuration parsing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File loading failed.
    #[error("configuration file could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The default config path list could not be read from `KRB5_CONFIG`.
    #[error("default configuration path list is not set in KRB5_CONFIG")]
    DefaultConfigName,
    /// A config path list contained no usable paths.
    #[error("configuration path list is empty")]
    EmptyConfigPathList,
    /// No environment or platform-default config file exists.
    #[error("no default Kerberos configuration file found")]
    NoDefaultConfig,
    /// A section line was syntactically invalid.
    #[error("invalid {section} section line {line}: {text}")]
    InvalidLine {
        /// Section name.
        section: &'static str,
        /// One-based line number.
        line: usize,
        /// Line text after comment stripping.
        text: String,
    },
    /// A directive is explicitly unsupported.
    #[error("{0}")]
    UnsupportedDirective(String),
    /// A boolean value was invalid.
    #[error("invalid boolean value: {0}")]
    InvalidBoolean(String),
    /// A duration value was invalid.
    #[error("invalid time duration value: {0}")]
    InvalidDuration(String),
    /// A duration value overflowed.
    #[error("time duration overflow: {0}")]
    DurationOverflow(String),
    /// An integer value was invalid.
    #[error("invalid integer for {key} on line {line}: {value}")]
    InvalidInteger {
        /// Line number.
        line: usize,
        /// Config key.
        key: String,
        /// Config value.
        value: String,
    },
    /// An IP address was invalid.
    #[error("invalid IP address for {key} on line {line}: {value}")]
    InvalidIpAddress {
        /// Line number.
        line: usize,
        /// Config key.
        key: String,
        /// Config value.
        value: String,
    },
    /// The realms section has invalid brace structure.
    #[error("invalid realms section: {0}")]
    InvalidRealmsSection(String),
    /// The requested realm is absent.
    #[error("realm not configured: {0}")]
    NoRealm(String),
    /// The requested realm has no configured KDCs.
    #[error("realm has no configured KDCs: {0}")]
    NoKdc(String),
    /// The requested realm has no configured password-change servers.
    #[error("realm has no configured kpasswd servers: {0}")]
    NoKpasswdServer(String),
}

#[derive(Clone, Debug)]
struct Line {
    number: usize,
    text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    LibDefaults,
    Realms,
    DomainRealm,
    Unknown,
}

impl SectionKind {
    fn parse(line: &str) -> Option<Self> {
        let close = line.find(']')?;
        let section = line.strip_prefix('[')?.get(..close - 1)?.trim();
        Some(match section.to_ascii_lowercase().as_str() {
            "libdefaults" => Self::LibDefaults,
            "realms" => Self::Realms,
            "domain_realm" => Self::DomainRealm,
            _ => Self::Unknown,
        })
    }
}

fn apply_section(config: &mut Config, section: SectionKind, lines: &[Line]) -> Result<(), Error> {
    match section {
        SectionKind::LibDefaults => config.libdefaults.parse_lines(lines),
        SectionKind::Realms => {
            config.realms = parse_realms(lines)?;
            Ok(())
        }
        SectionKind::DomainRealm => parse_domain_realm(&mut config.domain_realm, lines),
        SectionKind::Unknown => Ok(()),
    }
}

fn strip_comments(line: &str) -> &str {
    let hash = line.find('#');
    let semicolon = line.find(';');
    match (hash, semicolon) {
        (Some(left), Some(right)) => &line[..left.min(right)],
        (Some(index), None) | (None, Some(index)) => &line[..index],
        (None, None) => line,
    }
}

fn parse_assignment<'a>(
    line: &'a Line,
    section: &'static str,
) -> Result<(&'a str, &'a str), Error> {
    let Some((key, value)) = line.text.split_once('=') else {
        return Err(Error::InvalidLine {
            section,
            line: line.number,
            text: line.text.clone(),
        });
    };
    Ok((key.trim(), value.trim()))
}

fn parse_domain_realm(
    domain_realm: &mut BTreeMap<String, String>,
    lines: &[Line],
) -> Result<(), Error> {
    for line in lines {
        let (domain, realm) = parse_assignment(line, "domain_realm")?;
        domain_realm.insert(domain.to_ascii_lowercase(), realm.to_owned());
    }
    Ok(())
}

fn parse_realms(lines: &[Line]) -> Result<Vec<Realm>, Error> {
    let mut realms = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line = &lines[index];
        let (name, value) = parse_assignment(line, "realms")?;
        if !value.contains('{') {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} does not start with '{{'"
            )));
        }

        let mut depth = brace_delta(value);
        if depth < 0 {
            return Err(Error::InvalidRealmsSection(
                "unpaired closing brace".to_owned(),
            ));
        }

        let mut block = Vec::new();
        index += 1;

        while index < lines.len() && depth > 0 {
            let block_line = &lines[index];
            if depth == 1 && !block_line.text.trim().starts_with('}') {
                block.push(block_line.clone());
            }

            depth += brace_delta(&block_line.text);
            if depth < 0 {
                return Err(Error::InvalidRealmsSection(
                    "unpaired closing brace".to_owned(),
                ));
            }
            index += 1;
        }

        if depth != 0 {
            return Err(Error::InvalidRealmsSection(format!(
                "realm block for {name} is not closed"
            )));
        }

        realms.push(Realm::parse(name, &block)?);
    }

    Ok(realms)
}

fn brace_delta(value: &str) -> i32 {
    value.matches('{').count() as i32 - value.matches('}').count() as i32
}

/// Parse a krb5 duration value.
///
/// Supported forms match gokrb5's `parseDuration`: seconds (`100`), unit
/// suffixes (`12h30m15s`), days plus suffixes (`1d12h`), and `h:m[:s]`.
pub fn parse_duration(value: &str) -> Result<Duration, Error> {
    let normalized = value.split_whitespace().collect::<String>();
    if normalized.is_empty() {
        return Err(Error::InvalidDuration(value.to_owned()));
    }

    if let Some((days, rest)) = normalized.split_once('d') {
        let days = days
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(value.to_owned()))?;
        let day_seconds = days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        let mut duration = Duration::from_secs(day_seconds);
        if !rest.is_empty() {
            duration = duration
                .checked_add(parse_unit_duration(rest, value)?)
                .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        }
        return Ok(duration);
    }

    if let Ok(duration) = parse_unit_duration(&normalized, value) {
        return Ok(duration);
    }

    if let Ok(seconds) = normalized.parse::<u64>()
        && seconds > 0
    {
        return Ok(Duration::from_secs(seconds));
    }

    if normalized.contains(':') {
        return parse_colon_duration(&normalized, value);
    }

    Err(Error::InvalidDuration(value.to_owned()))
}

/// Parse a krb5 boolean value.
pub fn parse_boolean(value: &str) -> Result<bool, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" => Ok(true),
        "0" | "f" | "false" | "n" | "no" => Ok(false),
        _ => Err(Error::InvalidBoolean(value.to_owned())),
    }
}

/// Parse enctype names to the subset of IDs implemented by gokrb5-compatible
/// crypto.
pub fn parse_supported_enctype_ids(enctypes: &[String], allow_weak_crypto: bool) -> Vec<i32> {
    enctypes
        .iter()
        .filter(|name| allow_weak_crypto || !is_weak_enctype(name))
        .filter_map(|name| supported_enctype_id(name))
        .collect()
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct ConfigJson<'a> {
    #[serde(rename = "LibDefaults")]
    libdefaults: LibDefaultsJson<'a>,
    #[serde(rename = "Realms")]
    realms: Vec<RealmJson<'a>>,
    #[serde(rename = "DomainRealm")]
    domain_realm: &'a BTreeMap<String, String>,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a Config> for ConfigJson<'a> {
    fn from(config: &'a Config) -> Self {
        Self {
            libdefaults: LibDefaultsJson::from(&config.libdefaults),
            realms: config.realms.iter().map(RealmJson::from).collect(),
            domain_realm: &config.domain_realm,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct LibDefaultsJson<'a> {
    #[serde(rename = "AllowWeakCrypto")]
    allow_weak_crypto: bool,
    #[serde(rename = "Canonicalize")]
    canonicalize: bool,
    #[serde(rename = "CCacheType")]
    ccache_type: i32,
    #[serde(rename = "Clockskew")]
    clockskew: u128,
    #[serde(rename = "DefaultCCacheName")]
    default_ccache_name: &'a str,
    #[serde(rename = "DefaultClientKeytabName")]
    default_client_keytab_name: &'a str,
    #[serde(rename = "DefaultKeytabName")]
    default_keytab_name: &'a str,
    #[serde(rename = "DefaultRealm")]
    default_realm: &'a str,
    #[serde(rename = "DefaultTGSEnctypes")]
    default_tgs_enctypes: &'a [String],
    #[serde(rename = "DefaultTktEnctypes")]
    default_tkt_enctypes: &'a [String],
    #[serde(rename = "DefaultTGSEnctypeIDs")]
    default_tgs_enctype_ids: &'a [i32],
    #[serde(rename = "DefaultTktEnctypeIDs")]
    default_tkt_enctype_ids: &'a [i32],
    #[serde(rename = "DNSCanonicalizeHostname")]
    dns_canonicalize_hostname: bool,
    #[serde(rename = "DNSLookupKDC")]
    dns_lookup_kdc: bool,
    #[serde(rename = "DNSLookupRealm")]
    dns_lookup_realm: bool,
    #[serde(rename = "ExtraAddresses")]
    extra_addresses: Option<Vec<String>>,
    #[serde(rename = "Forwardable")]
    forwardable: bool,
    #[serde(rename = "IgnoreAcceptorHostname")]
    ignore_acceptor_hostname: bool,
    #[serde(rename = "K5LoginAuthoritative")]
    k5login_authoritative: bool,
    #[serde(rename = "K5LoginDirectory")]
    k5login_directory: &'a str,
    #[serde(rename = "KDCDefaultOptions")]
    kdc_default_options: KerberosBitStringJson,
    #[serde(rename = "KDCTimeSync")]
    kdc_time_sync: i32,
    #[serde(rename = "NoAddresses")]
    no_addresses: bool,
    #[serde(rename = "PermittedEnctypes")]
    permitted_enctypes: &'a [String],
    #[serde(rename = "PermittedEnctypeIDs")]
    permitted_enctype_ids: &'a [i32],
    #[serde(rename = "PreferredPreauthTypes")]
    preferred_preauth_types: &'a [i32],
    #[serde(rename = "Proxiable")]
    proxiable: bool,
    #[serde(rename = "RDNS")]
    rdns: bool,
    #[serde(rename = "RealmTryDomains")]
    realm_try_domains: i32,
    #[serde(rename = "RenewLifetime")]
    renew_lifetime: u128,
    #[serde(rename = "SafeChecksumType")]
    safe_checksum_type: i32,
    #[serde(rename = "TicketLifetime")]
    ticket_lifetime: u128,
    #[serde(rename = "UDPPreferenceLimit")]
    udp_preference_limit: i32,
    #[serde(rename = "VerifyAPReqNofail")]
    verify_ap_req_nofail: bool,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a LibDefaults> for LibDefaultsJson<'a> {
    fn from(libdefaults: &'a LibDefaults) -> Self {
        Self {
            allow_weak_crypto: libdefaults.allow_weak_crypto,
            canonicalize: libdefaults.canonicalize,
            ccache_type: libdefaults.ccache_type,
            clockskew: duration_nanos(libdefaults.clockskew),
            default_ccache_name: &libdefaults.default_ccache_name,
            default_client_keytab_name: &libdefaults.default_client_keytab_name,
            default_keytab_name: &libdefaults.default_keytab_name,
            default_realm: &libdefaults.default_realm,
            default_tgs_enctypes: &libdefaults.default_tgs_enctypes,
            default_tkt_enctypes: &libdefaults.default_tkt_enctypes,
            default_tgs_enctype_ids: &libdefaults.default_tgs_enctype_ids,
            default_tkt_enctype_ids: &libdefaults.default_tkt_enctype_ids,
            dns_canonicalize_hostname: libdefaults.dns_canonicalize_hostname,
            dns_lookup_kdc: libdefaults.dns_lookup_kdc,
            dns_lookup_realm: libdefaults.dns_lookup_realm,
            extra_addresses: optional_ip_addresses(&libdefaults.extra_addresses),
            forwardable: libdefaults.forwardable,
            ignore_acceptor_hostname: libdefaults.ignore_acceptor_hostname,
            k5login_authoritative: libdefaults.k5login_authoritative,
            k5login_directory: &libdefaults.k5login_directory,
            kdc_default_options: KerberosBitStringJson::from_u32(libdefaults.kdc_default_options),
            kdc_time_sync: libdefaults.kdc_time_sync,
            no_addresses: libdefaults.no_addresses,
            permitted_enctypes: &libdefaults.permitted_enctypes,
            permitted_enctype_ids: &libdefaults.permitted_enctype_ids,
            preferred_preauth_types: &libdefaults.preferred_preauth_types,
            proxiable: libdefaults.proxiable,
            rdns: libdefaults.rdns,
            realm_try_domains: libdefaults.realm_try_domains,
            renew_lifetime: duration_nanos(libdefaults.renew_lifetime),
            safe_checksum_type: libdefaults.safe_checksum_type,
            ticket_lifetime: duration_nanos(libdefaults.ticket_lifetime),
            udp_preference_limit: libdefaults.udp_preference_limit,
            verify_ap_req_nofail: libdefaults.verify_ap_req_nofail,
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct RealmJson<'a> {
    #[serde(rename = "Realm")]
    realm: &'a str,
    #[serde(rename = "AdminServer")]
    admin_server: Option<&'a [String]>,
    #[serde(rename = "DefaultDomain")]
    default_domain: &'a str,
    #[serde(rename = "KDC")]
    kdc: Option<&'a [String]>,
    #[serde(rename = "KPasswdServer")]
    kpasswd_server: Option<&'a [String]>,
    #[serde(rename = "MasterKDC")]
    master_kdc: Option<&'a [String]>,
}

#[cfg(feature = "serde")]
impl<'a> From<&'a Realm> for RealmJson<'a> {
    fn from(realm: &'a Realm) -> Self {
        Self {
            realm: &realm.realm,
            admin_server: optional_slice(&realm.admin_server),
            default_domain: &realm.default_domain,
            kdc: optional_slice(&realm.kdc),
            kpasswd_server: optional_slice(&realm.kpasswd_server),
            master_kdc: optional_slice(&realm.master_kdc),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct KerberosBitStringJson {
    #[serde(rename = "Bytes")]
    bytes: String,
    #[serde(rename = "BitLength")]
    bit_length: usize,
}

#[cfg(feature = "serde")]
impl KerberosBitStringJson {
    fn from_u32(value: u32) -> Self {
        Self {
            bytes: base64_standard(&value.to_be_bytes()),
            bit_length: u32::BITS as usize,
        }
    }
}

#[cfg(feature = "serde")]
fn optional_slice<T>(values: &[T]) -> Option<&[T]> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(feature = "serde")]
fn optional_ip_addresses(values: &[IpAddr]) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(ToString::to_string).collect())
    }
}

#[cfg(feature = "serde")]
fn duration_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

#[cfg(feature = "serde")]
fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = ((first as u32) << 16) | ((second as u32) << 8) | third as u32;

        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn parse_unit_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let mut chars = input.char_indices().peekable();
    let mut duration = Duration::ZERO;
    let mut parsed_any = false;

    while chars.peek().is_some() {
        let start = chars.peek().map_or(0, |(index, _)| *index);
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_digit()) {
            chars.next();
        }
        let number_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        if number_end == start {
            return Err(Error::InvalidDuration(original.to_owned()));
        }
        let number = input[start..number_end]
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(original.to_owned()))?;

        let unit_start = number_end;
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_alphabetic()) {
            chars.next();
        }
        let unit_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        let unit = &input[unit_start..unit_end];
        let seconds = match unit {
            "h" => number
                .checked_mul(60 * 60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "m" => number
                .checked_mul(60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "s" => number,
            _ => return Err(Error::InvalidDuration(original.to_owned())),
        };
        duration = duration
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
        parsed_any = true;
    }

    if parsed_any {
        Ok(duration)
    } else {
        Err(Error::InvalidDuration(original.to_owned()))
    }
}

fn parse_colon_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let parts = input.split(':').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) {
        return Err(Error::InvalidDuration(original.to_owned()));
    }
    let hours = parts[0]
        .parse::<u64>()
        .map_err(|_| Error::InvalidDuration(original.to_owned()))?;
    let minutes = parts[1]
        .parse::<u64>()
        .map_err(|_| Error::InvalidDuration(original.to_owned()))?;
    let seconds = if let Some(value) = parts.get(2) {
        value
            .parse::<u64>()
            .map_err(|_| Error::InvalidDuration(original.to_owned()))?
    } else {
        0
    };

    let total = hours
        .checked_mul(60 * 60)
        .and_then(|value| value.checked_add(minutes.checked_mul(60)?))
        .and_then(|value| value.checked_add(seconds))
        .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
    Ok(Duration::from_secs(total))
}

fn parse_i32(value: &str, line: &Line, key: &str) -> Result<i32, Error> {
    value.parse().map_err(|_| invalid_integer(value, line, key))
}

fn parse_i32_list(value: &str, line: &Line, key: &str) -> Result<Vec<i32>, Error> {
    value
        .split([',', ' ', '\t'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_i32(part.trim(), line, key))
        .collect()
}

fn parse_hex_u32(value: &str, line: &Line, key: &str) -> Result<u32, Error> {
    let value = value.trim().trim_start_matches("0x");
    u32::from_str_radix(value, 16).map_err(|_| invalid_integer(value, line, key))
}

fn invalid_integer(value: &str, line: &Line, key: &str) -> Error {
    Error::InvalidInteger {
        line: line.number,
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

fn parse_ip_addresses(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect()
}

fn parse_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|value| value.to_owned())
        .collect()
}

fn add_default_port(value: &str, port: u16) -> String {
    let trimmed = value.trim();
    let final_marker = trimmed.ends_with('*');
    let host = trimmed.trim_end_matches('*').trim();
    if host.contains(':') {
        if final_marker {
            format!("{host}*")
        } else {
            host.to_owned()
        }
    } else if final_marker {
        format!("{host}:{port}*")
    } else {
        format!("{host}:{port}")
    }
}

fn append_until_final(values: &mut Vec<String>, value: &str, final_seen: &mut bool) {
    if *final_seen {
        return;
    }

    let mut value = value.trim();
    if let Some(stripped) = value.strip_suffix('*') {
        *final_seen = true;
        value = stripped.trim_end();
    }
    values.push(value.to_owned());
}

fn supported_enctype_id(value: &str) -> Option<i32> {
    Some(match value.to_ascii_lowercase().as_str() {
        "aes128-cts-hmac-sha1-96" | "aes128-cts" | "aes128-sha1" => 17,
        "aes256-cts-hmac-sha1-96" | "aes256-cts" | "aes256-sha1" => 18,
        "aes128-cts-hmac-sha256-128" | "aes128-sha2" => 19,
        "aes256-cts-hmac-sha384-192" | "aes256-sha2" => 20,
        "des3-cbc-sha1-kd" => 16,
        "arcfour-hmac" | "rc4-hmac" | "arcfour-hmac-md5" => 23,
        _ => return None,
    })
}

fn is_weak_enctype(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "des-cbc-crc"
            | "des-cbc-md4"
            | "des-cbc-md5"
            | "des-cbc-raw"
            | "des3-cbc-raw"
            | "des-hmac-sha1"
            | "arcfour-hmac-exp"
            | "rc4-hmac-exp"
            | "arcfour-hmac-md5-exp"
            | "des"
    )
}

#[cfg(test)]
mod tests {
    use super::{Config, Error};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_default_paths_loads_existing_platform_candidate() {
        let path = temp_file("load-default-paths");
        std::fs::write(
            &path,
            r#"
[libdefaults]
 default_realm = DEFAULT.GOKRB5
"#,
        )
        .expect("default config writes");

        let config =
            Config::load_default_paths([PathBuf::from("/missing/krb5.conf"), path.clone()])
                .expect("existing default path loads");
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.libdefaults.default_realm, "DEFAULT.GOKRB5");
    }

    #[test]
    fn load_default_or_parse_paths_uses_embedded_when_no_default_exists() {
        let config = Config::load_default_or_parse_paths(
            r#"
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
"#,
            [PathBuf::from("/missing/krb5.conf")],
        )
        .expect("embedded config parses");

        assert_eq!(config.libdefaults.default_realm, "EMBEDDED.GOKRB5");
    }

    #[test]
    fn load_default_or_parse_paths_does_not_fallback_when_default_is_invalid() {
        let path = temp_file("load-default-invalid");
        std::fs::write(
            &path,
            r#"
[libdefaults]
 dns_lookup_kdc = maybe
"#,
        )
        .expect("invalid default config writes");

        let error = Config::load_default_or_parse_paths(
            r#"
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
"#,
            [path.clone()],
        )
        .expect_err("invalid existing default is returned");
        let _ = std::fs::remove_file(&path);

        assert!(matches!(error, Error::InvalidBoolean(value) if value == "maybe"));
    }

    fn temp_file(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rskrb5-config-unit-{name}-{}-{nanos}",
            std::process::id()
        ))
    }
}
