//! AP-REQ service-side validation.
//!
//! This module validates Kerberos AP-REQ messages by decoding the request,
//! decrypting the service ticket from a keytab, decrypting the authenticator
//! with the ticket session key, and enforcing the core identity, ticket-time,
//! clock-skew, address, and replay checks from gokrb5's service tests. It also
//! builds and verifies AP-REP mutual-auth replies using the AP-REQ
//! authenticator timestamp.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::keytab::{EncryptionKey, Keytab};
use crate::pac::{self, Pac};

const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
const INVALID_TICKET_FLAG: usize = 7;

/// Kerberos principal identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Principal components joined by `/`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Host address used for optional ticket address validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAddress {
    /// Kerberos host address type.
    pub addr_type: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// Construct an IPv4 host address.
    pub fn ipv4(address: [u8; 4]) -> Self {
        Self {
            addr_type: 2,
            address: address.to_vec(),
        }
    }
}

/// Successful AP-REQ validation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedApReq {
    /// Client identity from the authenticator.
    pub client: Principal,
    /// Service identity from the ticket.
    pub service: Principal,
    /// Ticket session key used to decrypt the authenticator.
    pub session_key: EncryptionKey,
    /// Optional subkey supplied by the client authenticator.
    pub subkey: Option<EncryptionKey>,
    /// Optional sequence number supplied by the client authenticator.
    pub sequence_number: Option<u32>,
    /// Ticket start time, or auth time when start time is absent.
    pub ticket_start: SystemTime,
    /// Ticket end time.
    pub ticket_end: SystemTime,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Verified PAC from the ticket authorization data, when present.
    pub pac: Option<Pac>,
}

impl ValidatedApReq {
    /// Build an AP-REP mutual-auth reply with an explicit confounder.
    ///
    /// The explicit confounder keeps tests deterministic and lets callers
    /// choose their own randomness policy. The AP-REP encrypted part is
    /// encrypted with the ticket session key using key usage 12.
    pub fn build_ap_rep_with_confounder(
        &self,
        confounder: &[u8],
        options: ApRepOptions,
    ) -> Result<Vec<u8>, Error> {
        let enc_part = rasn_kerberos::EncApRepPart {
            ctime: kerberos_time_from_system_time(self.authenticator_ctime)?,
            cusec: rasn::types::Integer::from(self.authenticator_cusec),
            subkey: options.subkey.as_ref().map(encryption_key_to_rasn),
            seq_number: options.sequence_number,
        };
        let ap_rep = crate::ap_rep::build_ap_rep_with_confounder(
            &enc_part,
            &self.session_key,
            options.kvno,
            confounder,
        )
        .map_err(ap_rep_error)?;
        crate::ap_rep::encode_ap_rep(&ap_rep).map_err(ap_rep_error)
    }

    /// Verify an AP-REP mutual-auth reply against this AP-REQ.
    ///
    /// The reply must use the same client timestamp from the AP-REQ
    /// authenticator. A verified AP-REP may carry a server-selected subkey and
    /// sequence number.
    pub fn verify_ap_rep(&self, bytes: &[u8]) -> Result<VerifiedApRep, Error> {
        let ap_rep = crate::ap_rep::decode_ap_rep(bytes).map_err(ap_rep_error)?;
        let enc_part = crate::ap_rep::decrypt_ap_rep_enc_part(&ap_rep, &self.session_key)
            .map_err(ap_rep_error)?;
        let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
        let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
        let authenticator_time = ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;

        if ctime != self.authenticator_ctime || cusec != self.authenticator_cusec {
            return Err(Error::ApRepTimestampMismatch {
                expected: self.authenticator_time,
                actual: authenticator_time,
            });
        }

        Ok(VerifiedApRep {
            ctime,
            cusec,
            authenticator_time,
            subkey: enc_part
                .subkey
                .as_ref()
                .map(encryption_key_from_rasn)
                .transpose()?,
            sequence_number: enc_part.seq_number,
        })
    }
}

/// Options for constructing an AP-REP mutual-auth reply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApRepOptions {
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
    /// Optional encrypted-data key version number.
    pub kvno: Option<u32>,
}

/// Verified AP-REP mutual-auth reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

/// In-memory AP-REQ replay cache.
#[derive(Debug, Default)]
pub struct ReplayCache {
    entries: HashMap<ReplayKey, SystemTime>,
}

impl ReplayCache {
    /// Create an empty replay cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all cached replay entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of cached replay entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the replay cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries presented more than `max_age` ago.
    pub fn clear_older_than(&mut self, max_age: Duration) -> usize {
        self.clear_older_than_at(max_age, SystemTime::now())
    }

    /// Remove entries presented more than `max_age` before `now`.
    pub fn clear_older_than_at(&mut self, max_age: Duration, now: SystemTime) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, presented_at| {
            now.duration_since(*presented_at)
                .map_or(true, |age| age <= max_age)
        });
        before - self.entries.len()
    }

    fn insert(&mut self, key: ReplayKey, presented_at: SystemTime) -> bool {
        self.entries.insert(key, presented_at).is_none()
    }
}

/// Shareable in-memory AP-REQ replay cache.
///
/// This is useful when a service framework clones middleware or builds several
/// service instances from the same acceptor state.
#[derive(Clone, Debug, Default)]
pub struct SharedReplayCache {
    inner: Arc<Mutex<ReplayCache>>,
}

impl SharedReplayCache {
    /// Create an empty shared replay cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a shared replay cache from an existing in-memory cache.
    pub fn from_cache(cache: ReplayCache) -> Self {
        Self {
            inner: Arc::new(Mutex::new(cache)),
        }
    }

    /// Remove all cached replay entries.
    pub fn clear(&self) -> Result<(), Error> {
        self.with_cache_mut(ReplayCache::clear)
    }

    /// Number of cached replay entries.
    pub fn len(&self) -> Result<usize, Error> {
        self.with_cache(ReplayCache::len)
    }

    /// Whether the replay cache is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.with_cache(ReplayCache::is_empty)
    }

    /// Remove entries presented more than `max_age` ago.
    pub fn clear_older_than(&self, max_age: Duration) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.clear_older_than(max_age))
    }

    /// Remove entries presented more than `max_age` before `now`.
    pub fn clear_older_than_at(&self, max_age: Duration, now: SystemTime) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.clear_older_than_at(max_age, now))
    }

    fn insert(&self, key: ReplayKey, presented_at: SystemTime) -> Result<bool, Error> {
        self.with_cache_mut(|cache| cache.insert(key, presented_at))
    }

    fn with_cache<R>(&self, f: impl FnOnce(&ReplayCache) -> R) -> Result<R, Error> {
        let cache = self.inner.lock().map_err(|_| Error::ReplayCachePoisoned)?;
        Ok(f(&cache))
    }

    fn with_cache_mut<R>(&self, f: impl FnOnce(&mut ReplayCache) -> R) -> Result<R, Error> {
        let mut cache = self.inner.lock().map_err(|_| Error::ReplayCachePoisoned)?;
        Ok(f(&mut cache))
    }
}

/// AP-REQ validator backed by a service keytab.
#[derive(Debug)]
pub struct ServiceValidator<'a> {
    keytab: Cow<'a, Keytab>,
    max_clock_skew: Duration,
    now: Option<SystemTime>,
    keytab_principal: Option<Vec<String>>,
    client_address: Option<HostAddress>,
    require_client_address: bool,
    replay_cache: ReplayCache,
    shared_replay_cache: Option<SharedReplayCache>,
}

impl<'a> ServiceValidator<'a> {
    /// Create a validator with gokrb5-compatible defaults.
    pub fn new(keytab: &'a Keytab) -> Self {
        Self::from_keytab_cow(Cow::Borrowed(keytab))
    }

    pub(crate) fn from_keytab_cow(keytab: Cow<'a, Keytab>) -> Self {
        Self {
            keytab,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            now: None,
            keytab_principal: None,
            client_address: None,
            require_client_address: false,
            replay_cache: ReplayCache::new(),
            shared_replay_cache: None,
        }
    }

    /// Override the validation clock. Useful for deterministic tests.
    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Override the maximum accepted clock skew.
    pub fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Self {
        self.max_clock_skew = max_clock_skew;
        self
    }

    /// Override the principal used for keytab lookup.
    ///
    /// The ticket realm remains the lookup realm, matching gokrb5's
    /// `KeytabPrincipal` behavior.
    pub fn with_keytab_principal<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keytab_principal = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Provide the client address observed by the service.
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.client_address = Some(client_address);
        self
    }

    /// Require the ticket to contain client addresses.
    pub fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.require_client_address = require_client_address;
        self
    }

    /// Share replay detection state with other validators.
    pub fn with_shared_replay_cache(mut self, replay_cache: SharedReplayCache) -> Self {
        self.shared_replay_cache = Some(replay_cache);
        self
    }

    /// Remove any shared replay cache and use this validator's local cache.
    pub fn without_shared_replay_cache(mut self) -> Self {
        self.shared_replay_cache = None;
        self
    }

    /// Shared replay cache used by this validator, if any.
    pub fn shared_replay_cache(&self) -> Option<&SharedReplayCache> {
        self.shared_replay_cache.as_ref()
    }

    /// Mutable replay cache for tests and integration with service state.
    ///
    /// If a shared replay cache has been installed, validation uses the shared
    /// cache instead of this local cache.
    pub fn replay_cache_mut(&mut self) -> &mut ReplayCache {
        &mut self.replay_cache
    }

    /// Decode and validate an AP-REQ.
    pub fn validate_ap_req(&mut self, bytes: &[u8]) -> Result<ValidatedApReq, Error> {
        let ap_req = crate::ap_req::decode_ap_req(bytes).map_err(ap_req_error)?;

        let ticket_service = principal_from_parts(&ap_req.ticket.realm, &ap_req.ticket.sname)?;
        let ticket_etype = ap_req.ticket.enc_part.etype;
        let ticket_kvno = ap_req.ticket.enc_part.kvno.unwrap_or(0);
        let keytab_components = self
            .keytab_principal
            .clone()
            .unwrap_or_else(|| ticket_service.components.clone());
        let keytab_refs = keytab_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let service_key = self.keytab.find_key(
            &keytab_refs,
            &ticket_service.realm,
            ticket_kvno,
            ticket_etype,
        )?;

        let enc_ticket = crate::ticket::decrypt_ticket_enc_part(&ap_req.ticket, service_key.0)
            .map_err(ticket_error)?;
        self.validate_ticket_times(&ticket_service, &enc_ticket)?;
        self.validate_client_address(&ticket_service, &enc_ticket)?;
        let pac = match &enc_ticket.authorization_data {
            Some(authorization_data) => pac::find_pac_in_authorization_data(authorization_data)?,
            None => None,
        };
        if let Some(pac) = &pac {
            pac.verify(service_key.0)?;
        }

        let session_key = encryption_key_from_rasn(&enc_ticket.key)?;
        let authenticator_usage = crate::ap_req::authenticator_usage_for_ticket(&ap_req.ticket);
        let authenticator =
            crate::ap_req::decrypt_ap_req_authenticator(&ap_req, &session_key, authenticator_usage)
                .map_err(ap_req_error)?;

        let ticket_client = principal_from_parts(&enc_ticket.crealm, &enc_ticket.cname)?;
        let authenticator_client =
            principal_from_parts(&authenticator.crealm, &authenticator.cname)?;
        if authenticator_client.components != ticket_client.components {
            return Err(Error::ClientPrincipalMismatch {
                ticket: ticket_client.name(),
                authenticator: authenticator_client.name(),
            });
        }

        let cusec = integer_to_u32("authenticator.cusec", &authenticator.cusec)?;
        let authenticator_ctime = system_time_from_kerberos_time(&authenticator.ctime)?;
        let authenticator_time = authenticator_ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;
        let now = self.now();
        if abs_duration(now, authenticator_time) > self.max_clock_skew {
            return Err(Error::ClockSkew {
                max_clock_skew: self.max_clock_skew,
            });
        }

        let replay_key = ReplayKey {
            service: ticket_service.clone(),
            client: authenticator_client.clone(),
            ctime_seconds: authenticator.ctime.0.timestamp(),
            cusec,
        };
        self.record_replay(replay_key, now)?;

        Ok(ValidatedApReq {
            client: authenticator_client,
            service: ticket_service,
            session_key,
            subkey: authenticator
                .subkey
                .as_ref()
                .map(encryption_key_from_rasn)
                .transpose()?,
            sequence_number: authenticator.seq_number,
            ticket_start: ticket_start_time(&enc_ticket)?,
            ticket_end: system_time_from_kerberos_time(&enc_ticket.end_time)?,
            authenticator_ctime,
            authenticator_cusec: cusec,
            authenticator_time,
            pac,
        })
    }

    fn now(&self) -> SystemTime {
        self.now.unwrap_or_else(SystemTime::now)
    }

    fn record_replay(&mut self, replay_key: ReplayKey, now: SystemTime) -> Result<(), Error> {
        let inserted = if let Some(replay_cache) = &self.shared_replay_cache {
            replay_cache.insert(replay_key, now)?
        } else {
            self.replay_cache.insert(replay_key, now)
        };
        if inserted { Ok(()) } else { Err(Error::Replay) }
    }

    fn validate_ticket_times(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let now = self.now();
        let start = ticket_start_time(enc_ticket)?;
        if starts_after_skew(start, now, self.max_clock_skew) || has_invalid_flag(&enc_ticket.flags)
        {
            return Err(Error::TicketNotYetValid {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        let end = system_time_from_kerberos_time(&enc_ticket.end_time)?;
        if expired_after_skew(now, end, self.max_clock_skew) {
            return Err(Error::TicketExpired {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        Ok(())
    }

    fn validate_client_address(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let Some(ticket_addresses) = &enc_ticket.caddr else {
            if self.require_client_address {
                return Err(Error::RequiredClientAddressMissing {
                    service: service.name(),
                    realm: service.realm.clone(),
                });
            }
            return Ok(());
        };

        let Some(client_address) = &self.client_address else {
            return Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            });
        };

        if ticket_addresses.iter().any(|address| {
            address.addr_type == client_address.addr_type
                && address.address.as_ref() == client_address.address.as_slice()
        }) {
            Ok(())
        } else {
            Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            })
        }
    }
}

impl ServiceValidator<'static> {
    /// Create a validator from an owned keytab.
    pub fn from_keytab(keytab: Keytab) -> Self {
        Self::from_keytab_cow(Cow::Owned(keytab))
    }

    /// Create a validator by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    pub fn from_keytab_name(keytab_name: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self::from_keytab(Keytab::load_name(keytab_name)?))
    }

    /// Create a validator from `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab_name(config: &Config) -> Result<Self, Error> {
        Self::from_keytab_name(&config.libdefaults.default_keytab_name)
    }

    /// Create a validator from the default keytab.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`.
    pub fn from_default_keytab(config: &Config) -> Result<Self, Error> {
        Self::from_keytab_name(crate::keytab::default_keytab_name(
            &config.libdefaults.default_keytab_name,
        )?)
    }

    /// Create a validator by loading the file keytab named by `KRB5_KTNAME`.
    pub fn from_keytab_env() -> Result<Self, Error> {
        Ok(Self::from_keytab(Keytab::load_from_env()?))
    }
}

/// AP-REQ service validation error.
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

    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
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

    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    ApRepKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    ApReqKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Service key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// Keytab lookup failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] crate::keytab::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// PAC parsing or verification failed.
    #[error("PAC error: {0}")]
    Pac(#[from] crate::pac::Error),

    /// Ticket has not become valid or carries the invalid ticket flag.
    #[error("ticket for {service}@{realm} is not yet valid")]
    TicketNotYetValid {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },

    /// Ticket has expired.
    #[error("ticket for {service}@{realm} has expired")]
    TicketExpired {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },

    /// Ticket client and authenticator client do not match.
    #[error("authenticator client {authenticator} does not match ticket client {ticket}")]
    ClientPrincipalMismatch {
        /// Ticket client principal components.
        ticket: String,
        /// Authenticator client principal components.
        authenticator: String,
    },

    /// Authenticator timestamp exceeded the accepted clock skew.
    #[error("authenticator clock skew exceeds {max_clock_skew:?}")]
    ClockSkew {
        /// Maximum accepted skew.
        max_clock_skew: Duration,
    },

    /// AP-REQ replay detected.
    #[error("AP-REQ replay detected")]
    Replay,

    /// Shared replay cache lock could not be acquired.
    #[error("shared replay cache lock is poisoned")]
    ReplayCachePoisoned,

    /// AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    ApRepTimestampMismatch {
        /// Expected AP-REQ authenticator timestamp.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
    },

    /// Ticket client address list did not include the observed client address.
    #[error("client address not accepted for ticket {service}@{realm}")]
    BadClientAddress {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },

    /// The service requires client addresses but the ticket is addressless.
    #[error("ticket for {service}@{realm} does not contain required client addresses")]
    RequiredClientAddressMissing {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    service: Principal,
    client: Principal,
    ctime_seconds: i64,
    cusec: u32,
}

fn ap_req_error(error: crate::ap_req::Error) -> Error {
    match error {
        crate::ap_req::Error::Decode { target, message } => Error::Decode { target, message },
        crate::ap_req::Error::Encode { target, message } => Error::Encode { target, message },
        crate::ap_req::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::ap_req::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::ap_req::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApReqKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::ap_req::Error::Random(source) => Error::Random(source),
        crate::ap_req::Error::Crypto(source) => Error::Crypto(source),
    }
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

fn ap_rep_error(error: crate::ap_rep::Error) -> Error {
    match error {
        crate::ap_rep::Error::Decode { target, message } => Error::Decode { target, message },
        crate::ap_rep::Error::Encode { target, message } => Error::Encode { target, message },
        crate::ap_rep::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        crate::ap_rep::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        crate::ap_rep::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApRepKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        crate::ap_rep::Error::Random(source) => Error::Random(source),
        crate::ap_rep::Error::Crypto(source) => Error::Crypto(source),
    }
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<Principal, Error> {
    Ok(Principal {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(std::str::from_utf8(value.as_bytes())?.to_owned())
}

fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> Result<EncryptionKey, Error> {
    Ok(EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    })
}

fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
    }
}

fn ticket_start_time(enc_ticket: &rasn_kerberos::EncTicketPart) -> Result<SystemTime, Error> {
    system_time_from_kerberos_time(
        enc_ticket
            .start_time
            .as_ref()
            .unwrap_or(&enc_ticket.auth_time),
    )
}

fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(seconds as u64, nanos))
            .ok_or(Error::TimeOverflow)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::new(seconds.unsigned_abs(), nanos))
            .ok_or(Error::TimeOverflow)
    }
}

fn kerberos_time_from_system_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, Error> {
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .ok_or(Error::TimeOverflow)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOverflow)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

fn unix_timestamp_parts(time: SystemTime) -> Result<(i64, u32), Error> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok((
            duration
                .as_secs()
                .try_into()
                .map_err(|_| Error::TimeOverflow)?,
            duration.subsec_nanos(),
        )),
        Err(source) => {
            let duration = source.duration();
            let seconds: i64 = duration
                .as_secs()
                .try_into()
                .map_err(|_| Error::TimeOverflow)?;
            if duration.subsec_nanos() == 0 {
                return Ok((-seconds, 0));
            }

            let seconds = seconds.checked_add(1).ok_or(Error::TimeOverflow)?;
            Ok((-seconds, 1_000_000_000 - duration.subsec_nanos()))
        }
    }
}

fn integer_to_u32(field: &'static str, value: &rasn::types::Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .map_err(|_| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

fn has_invalid_flag(flags: &rasn_kerberos::TicketFlags) -> bool {
    flags.0.get(INVALID_TICKET_FLAG).is_some_and(|bit| *bit)
}

fn starts_after_skew(start: SystemTime, now: SystemTime, max_clock_skew: Duration) -> bool {
    start
        .duration_since(now)
        .is_ok_and(|delta| delta > max_clock_skew)
}

fn expired_after_skew(now: SystemTime, end: SystemTime, max_clock_skew: Duration) -> bool {
    now.duration_since(end)
        .is_ok_and(|delta| delta > max_clock_skew)
}

fn abs_duration(left: SystemTime, right: SystemTime) -> Duration {
    left.duration_since(right)
        .or_else(|_| right.duration_since(left))
        .expect("one SystemTime must be later than the other")
}
