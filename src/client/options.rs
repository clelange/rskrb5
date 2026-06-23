use std::time::{Duration, SystemTime};

use crate::config::LibDefaults;
use crate::keytab::EncryptionKey;

use super::{
    DEFAULT_TGS_ENCTYPES, DEFAULT_TICKET_LIFETIME, DEFAULT_TKT_ENCTYPES, KDC_OPTION_CANONICALIZE,
    renewal_kdc_option_bits,
};

/// Options for constructing an AS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsReqOptions {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
    /// Optional preauthentication data.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ using requested etype defaults.
    pub assume_preauthentication: bool,
    /// Advertise support for AS-REP encrypted padata negotiation.
    pub fast_negotiation: bool,
}

impl AsReqOptions {
    /// Construct options with gokrb5-compatible AES defaults.
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TKT_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            assume_preauthentication: false,
            fast_negotiation: true,
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tkt_enctype_ids.is_empty() {
            DEFAULT_TKT_ENCTYPES.to_vec()
        } else {
            defaults.default_tkt_enctype_ids.clone()
        };
        options.kdc_option_bits = defaults.kdc_default_options;
        if defaults.canonicalize {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        options
    }

    /// Override the requested ticket lifetime.
    pub fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    /// Override the renewable lifetime.
    pub fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    /// Override requested response encryption types.
    pub fn with_etypes(mut self, etypes: impl Into<Vec<i32>>) -> Self {
        self.etypes = etypes.into();
        self
    }

    /// Override KDC options using the raw krb5.conf bit representation.
    pub fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    /// Add preauthentication data.
    pub fn with_padata(mut self, padata: impl Into<Vec<rasn_kerberos::PaData>>) -> Self {
        self.padata = padata.into();
        self
    }

    /// Send PA-ENC-TIMESTAMP in the first AS-REQ.
    pub fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }

    /// Configure whether high-level AS login advertises PA-REQ-ENC-PA-REP.
    pub fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
        self
    }
}

/// Options for constructing a TGS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TgsReqOptions {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested service-ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
    /// Additional TGS padata appended after PA-TGS-REQ.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Additional tickets included in the TGS request body.
    pub additional_tickets: Vec<rasn_kerberos::Ticket>,
}

impl TgsReqOptions {
    /// Construct options with gokrb5-compatible AES defaults.
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TGS_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            additional_tickets: Vec::new(),
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tgs_enctype_ids.is_empty() {
            DEFAULT_TGS_ENCTYPES.to_vec()
        } else {
            defaults.default_tgs_enctype_ids.clone()
        };
        options.kdc_option_bits = defaults.kdc_default_options;
        if defaults.canonicalize {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        options
    }

    /// Override the requested service-ticket lifetime.
    pub fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    /// Override the renewable lifetime.
    pub fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    /// Override requested response encryption types.
    pub fn with_etypes(mut self, etypes: impl Into<Vec<i32>>) -> Self {
        self.etypes = etypes.into();
        self
    }

    /// Override KDC options using the raw krb5.conf bit representation.
    pub fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    /// Add additional TGS padata.
    pub fn with_padata(mut self, padata: impl Into<Vec<rasn_kerberos::PaData>>) -> Self {
        self.padata = padata.into();
        self
    }

    /// Add additional tickets to the TGS request body.
    pub fn with_additional_tickets(
        mut self,
        additional_tickets: impl Into<Vec<rasn_kerberos::Ticket>>,
    ) -> Self {
        self.additional_tickets = additional_tickets.into();
        self
    }

    /// Add the TGS renewal flags used for renewing an existing ticket.
    pub fn with_renewal(mut self) -> Self {
        self.kdc_option_bits = renewal_kdc_option_bits(self.kdc_option_bits);
        self
    }
}

/// Options for constructing a client AP-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApReqOptions {
    /// Raw AP option bit string.
    pub ap_option_bits: u32,
    /// Optional authenticator checksum.
    pub checksum: Option<rasn_kerberos::Checksum>,
    /// Optional client-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    pub sequence_number: Option<u32>,
}

impl ApReqOptions {
    /// Construct AP-REQ options with no flags or optional authenticator fields.
    pub fn new() -> Self {
        Self {
            ap_option_bits: 0,
            checksum: None,
            subkey: None,
            sequence_number: None,
        }
    }

    /// Override AP-REQ option bits.
    pub fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
        self
    }

    /// Set or clear the authenticator checksum.
    pub fn with_checksum(mut self, checksum: Option<rasn_kerberos::Checksum>) -> Self {
        self.checksum = checksum;
        self
    }

    /// Set or clear the client-selected subkey.
    pub fn with_subkey(mut self, subkey: Option<EncryptionKey>) -> Self {
        self.subkey = subkey;
        self
    }

    /// Set or clear the client sequence number.
    pub fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self {
        self.sequence_number = sequence_number;
        self
    }
}

impl Default for ApReqOptions {
    fn default() -> Self {
        Self::new()
    }
}
