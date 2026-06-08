use std::fmt;

/// Candidate crates evaluated before committing to a standalone `rskrb5`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Candidate {
    /// `rasn-kerberos`, the `rasn` Kerberos ASN.1 type crate.
    RasnKerberos,
    /// `picky-krb`, Devolutions' Kerberos DER data crate.
    PickyKrb,
    /// `sspi`, Devolutions' SSPI implementation with Kerberos/Negotiate.
    SspiRs,
    /// `kerberos-parser`, Rusticata's parser crate.
    KerberosParser,
    /// The published `krb5-rs` crate.
    Krb5Rs,
    /// Kerbeiros-family crates and forks.
    KerbeirosFamily,
    /// `kenobi`, a cross-platform Negotiate client.
    Kenobi,
    /// HTTP Negotiate middleware crates.
    HttpNegotiateLayers,
    /// GSSAPI/SSPI wrapper crates such as `cross-krb5` and `libgssapi`.
    SystemGssapiWrappers,
}

impl Candidate {
    /// Display name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::RasnKerberos => "rasn-kerberos",
            Self::PickyKrb => "picky-krb",
            Self::SspiRs => "sspi-rs",
            Self::KerberosParser => "kerberos-parser",
            Self::Krb5Rs => "krb5-rs",
            Self::KerbeirosFamily => "kerbeiros/kerberos_*",
            Self::Kenobi => "kenobi",
            Self::HttpNegotiateLayers => "axum-negotiate-layer/axum-negotiate",
            Self::SystemGssapiWrappers => "cross-krb5/libgssapi",
        }
    }

    /// SPDX license expression observed for the candidate's crate.
    pub const fn license(self) -> &'static str {
        match self {
            Self::RasnKerberos => "MIT OR Apache-2.0",
            Self::PickyKrb => "MIT OR Apache-2.0",
            Self::SspiRs => "MIT OR Apache-2.0",
            Self::KerberosParser => "MIT OR Apache-2.0",
            Self::Krb5Rs => "Apache-2.0",
            Self::KerbeirosFamily => "AGPL-3.0",
            Self::Kenobi => "MIT",
            Self::HttpNegotiateLayers => "MIT / LGPL-3.0-or-later by crate",
            Self::SystemGssapiWrappers => "MIT",
        }
    }
}

/// Compatibility state for a gokrb5 capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Support {
    /// Candidate appears to cover the capability directly.
    Yes,
    /// Candidate covers part of the capability but cannot satisfy the gokrb5
    /// contract alone.
    Partial,
    /// Candidate does not provide this capability.
    No,
    /// Candidate should not be used for the core implementation.
    Excluded,
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Yes => "yes",
            Self::Partial => "partial",
            Self::No => "no",
            Self::Excluded => "excluded",
        })
    }
}

/// One row in the gokrb5 v8 parity contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractArea {
    /// Short identifier used in the candidate matrix.
    pub id: &'static str,
    /// Contract area from `gokrb5` v8.
    pub area: &'static str,
    /// Representative gokrb5 test files that define expected behavior.
    pub gokrb5_tests: &'static str,
    /// Environment gate for equivalent Rust tests.
    pub gate: &'static str,
    /// Porting note for Rust implementation work.
    pub porting_note: &'static str,
}

/// DER shape represented by a gokrb5 ASN.1 fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerType {
    /// RFC 4120 Authenticator.
    Authenticator,
    /// RFC 4120 Ticket.
    Ticket,
    /// RFC 4120 EncryptionKey.
    EncryptionKey,
    /// RFC 4120 encrypted ticket part.
    EncTicketPart,
    /// KDC request body.
    KdcReqBody,
    /// AS-REQ.
    AsReq,
    /// TGS-REQ.
    TgsReq,
    /// AS-REP.
    AsRep,
    /// TGS-REP.
    TgsRep,
    /// Encrypted TGS reply part.
    EncTgsRepPart,
    /// AP-REQ.
    ApReq,
    /// AP-REP.
    ApRep,
    /// Encrypted AP reply part.
    EncApRepPart,
    /// KRB-SAFE.
    KrbSafe,
    /// KRB-PRIV.
    KrbPriv,
    /// Encrypted KRB-PRIV part.
    EncKrbPrivPart,
    /// KRB-CRED.
    KrbCred,
    /// Encrypted KRB-CRED part.
    EncKrbCredPart,
    /// KRB-ERROR.
    KrbError,
    /// AuthorizationData sequence.
    AuthorizationData,
    /// AD-KDCIssued.
    AdKdcIssued,
    /// PA-DATA sequence / METHOD-DATA.
    PaDataSequence,
    /// TypedData sequence.
    TypedData,
    /// PA-ENC-TS-ENC.
    PaEncTsEnc,
    /// ETYPE-INFO.
    EtypeInfo,
    /// ETYPE-INFO2.
    EtypeInfo2,
    /// EncryptedData.
    EncryptedData,
    /// ChangePasswdData.
    ChangePasswdData,
}

impl DerType {
    /// Display name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authenticator => "Authenticator",
            Self::Ticket => "Ticket",
            Self::EncryptionKey => "EncryptionKey",
            Self::EncTicketPart => "EncTicketPart",
            Self::KdcReqBody => "KdcReqBody",
            Self::AsReq => "AS-REQ",
            Self::TgsReq => "TGS-REQ",
            Self::AsRep => "AS-REP",
            Self::TgsRep => "TGS-REP",
            Self::EncTgsRepPart => "EncTgsRepPart",
            Self::ApReq => "AP-REQ",
            Self::ApRep => "AP-REP",
            Self::EncApRepPart => "EncApRepPart",
            Self::KrbSafe => "KRB-SAFE",
            Self::KrbPriv => "KRB-PRIV",
            Self::EncKrbPrivPart => "EncKrbPrivPart",
            Self::KrbCred => "KRB-CRED",
            Self::EncKrbCredPart => "EncKrbCredPart",
            Self::KrbError => "KRB-ERROR",
            Self::AuthorizationData => "AuthorizationData",
            Self::AdKdcIssued => "AD-KDCIssued",
            Self::PaDataSequence => "PA-DATA sequence",
            Self::TypedData => "TypedData",
            Self::PaEncTsEnc => "PA-ENC-TS-ENC",
            Self::EtypeInfo => "ETYPE-INFO",
            Self::EtypeInfo2 => "ETYPE-INFO2",
            Self::EncryptedData => "EncryptedData",
            Self::ChangePasswdData => "ChangePasswdData",
        }
    }
}

/// One gokrb5 DER fixture used to measure candidate ASN.1 coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Fixture {
    /// Stable short id used by tests.
    pub id: &'static str,
    /// gokrb5 testdata constant name.
    pub gokrb5_constant: &'static str,
    /// gokrb5 test file where the fixture is exercised.
    pub gokrb5_test: &'static str,
    /// DER shape.
    pub der_type: DerType,
    /// Expected `rasn-kerberos` decode support for this fixture.
    pub rasn_kerberos: Support,
    /// Expected `rasn-kerberos` exact DER round-trip support for this fixture.
    pub rasn_kerberos_roundtrip: Support,
    /// Expected `picky-krb` decode support for this fixture.
    pub picky_krb: Support,
    /// Expected `picky-krb` exact DER round-trip support for this fixture.
    pub picky_krb_roundtrip: Support,
}

/// One row in a candidate-specific detail table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Capability area.
    pub area: &'static str,
    /// Evaluation result.
    pub support: Support,
    /// Concise explanation for the decision.
    pub note: &'static str,
}

/// Full candidate evaluation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateReport {
    /// Candidate crate/project.
    pub candidate: Candidate,
    /// Capability rows.
    pub capabilities: &'static [Capability],
    /// Overall recommendation.
    pub recommendation: &'static str,
}

/// Candidate support for a single contract area.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportByArea {
    /// `ContractArea::id`.
    pub area_id: &'static str,
    /// Candidate support level.
    pub support: Support,
}

/// Cross-product of a candidate and the gokrb5 v8 parity contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateAssessment {
    /// Candidate crate/project.
    pub candidate: Candidate,
    /// Support entries keyed by contract area id.
    pub support: &'static [SupportByArea],
}

impl CandidateAssessment {
    /// Return support for a contract area id.
    pub fn support_for(self, area_id: &str) -> Support {
        self.support
            .iter()
            .find(|entry| entry.area_id == area_id)
            .map_or(Support::No, |entry| entry.support)
    }
}

/// The gokrb5 v8 behavior that must be matched before `rskrb5` can claim parity.
pub const V8_CONTRACT: &[ContractArea] = &[
    ContractArea {
        id: "asn1",
        area: "ASN.1 / DER messages",
        gokrb5_tests: "messages/*_test.go, types/*_test.go, kadmin/*_test.go",
        gate: "unit",
        porting_note: "Translate fixture round-trip tests first; reuse permissive ASN.1 crates where they pass.",
    },
    ContractArea {
        id: "crypto",
        area: "Kerberos crypto vectors",
        gokrb5_tests: "crypto/**/*_test.go",
        gate: "unit",
        porting_note: "Use gokrb5/RFC vectors for string-to-key, checksum, encrypt, decrypt, and key usage behavior.",
    },
    ContractArea {
        id: "keytab",
        area: "keytab",
        gokrb5_tests: "keytab/keytab_test.go",
        gate: "unit",
        porting_note: "Parse/write keytabs and select keys by service principal, realm, kvno, and enctype.",
    },
    ContractArea {
        id: "ccache",
        area: "ccache",
        gokrb5_tests: "credentials/ccache_test.go, credentials/ccache_integration_test.go",
        gate: "unit, INTEGRATION=1",
        porting_note: "Implement MIT file ccache parsing/writing plus KDC-issued credential capture.",
    },
    ContractArea {
        id: "conf",
        area: "krb5.conf and host config",
        gokrb5_tests: "config/*_test.go",
        gate: "unit",
        porting_note: "Preserve gokrb5 parsing semantics, libdefaults, realm lookup, DNS flags, and host mappings.",
    },
    ContractArea {
        id: "client",
        area: "AS/TGS client flows",
        gokrb5_tests: "client/*_test.go",
        gate: "unit, INTEGRATION=1, TESTAD=1",
        porting_note: "Cover password/keytab login, TCP/UDP KDC transport, referrals, DNS KDC lookup, renewal, and service tickets.",
    },
    ContractArea {
        id: "service",
        area: "AP-REQ/AP-REP service validation",
        gokrb5_tests: "service/*_test.go, messages/Ticket_test.go",
        gate: "unit, INTEGRATION=1",
        porting_note: "Decrypt tickets, validate authenticators, enforce clock skew, provide replay cache hooks, and build/verify AP-REP mutual-auth replies.",
    },
    ContractArea {
        id: "spnego",
        area: "GSSAPI/SPNEGO HTTP",
        gokrb5_tests: "gssapi/*_test.go, spnego/*_test.go",
        gate: "unit, INTEGRATION=1",
        porting_note: "Implement tokens, wrap/MIC behavior, HTTP Negotiate helpers, and Tower/Axum adapters.",
    },
    ContractArea {
        id: "pac",
        area: "PAC / NDR",
        gokrb5_tests: "pac/*_test.go, messages/Ticket_test.go",
        gate: "unit, TESTAD=1",
        porting_note: "Parse PAC buffers, NDR validation info, claims, UPN/DNS info, and checksum verification.",
    },
    ContractArea {
        id: "docker",
        area: "Docker KDC integration",
        gokrb5_tests: "client/*_integration_test.go, credentials/*_integration_test.go, spnego/http_test.go",
        gate: "INTEGRATION=1, TESTPRIVILEGED=1, TESTAD=1",
        porting_note: "Reuse gokrb5 MIT KDC, DNS, short-ticket, referral-domain, HTTP, and AD gates where possible.",
    },
];

/// gokrb5 ASN.1 fixtures exercised by the translated unit-test spike.
pub const ASN1_FIXTURES: &[Asn1Fixture] = &[
    Asn1Fixture {
        id: "authenticator",
        gokrb5_constant: "MarshaledKRB5authenticator",
        gokrb5_test: "types/Authenticator_test.go",
        der_type: DerType::Authenticator,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "authenticator_optionals_empty",
        gokrb5_constant: "MarshaledKRB5authenticatorOptionalsEmpty",
        gokrb5_test: "types/Authenticator_test.go",
        der_type: DerType::Authenticator,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "authenticator_optionals_null",
        gokrb5_constant: "MarshaledKRB5authenticatorOptionalsNULL",
        gokrb5_test: "types/Authenticator_test.go",
        der_type: DerType::Authenticator,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "ticket",
        gokrb5_constant: "MarshaledKRB5ticket",
        gokrb5_test: "messages/Ticket_test.go",
        der_type: DerType::Ticket,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "encryption_key",
        gokrb5_constant: "MarshaledKRB5keyblock",
        gokrb5_test: "types/Cryptosystem_test.go",
        der_type: DerType::EncryptionKey,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_ticket_part",
        gokrb5_constant: "MarshaledKRB5enc_tkt_part",
        gokrb5_test: "messages/Ticket_test.go",
        der_type: DerType::EncTicketPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_ticket_part_optionals_null",
        gokrb5_constant: "MarshaledKRB5enc_tkt_partOptionalsNULL",
        gokrb5_test: "messages/Ticket_test.go",
        der_type: DerType::EncTicketPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "kdc_req_body",
        gokrb5_constant: "MarshaledKRB5kdc_req_body",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::KdcReqBody,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "kdc_req_body_optionals_null_except_second_ticket",
        gokrb5_constant: "MarshaledKRB5kdc_req_bodyOptionalsNULLexceptsecond_ticket",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::KdcReqBody,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "kdc_req_body_optionals_null_except_server",
        gokrb5_constant: "MarshaledKRB5kdc_req_bodyOptionalsNULLexceptserver",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::KdcReqBody,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "as_req",
        gokrb5_constant: "MarshaledKRB5as_req",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::AsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "as_req_optionals_null_except_second_ticket",
        gokrb5_constant: "MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::AsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "as_req_optionals_null_except_server",
        gokrb5_constant: "MarshaledKRB5as_reqOptionalsNULLexceptserver",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::AsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "tgs_req",
        gokrb5_constant: "MarshaledKRB5tgs_req",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::TgsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "tgs_req_optionals_null_except_second_ticket",
        gokrb5_constant: "MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::TgsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "tgs_req_optionals_null_except_server",
        gokrb5_constant: "MarshaledKRB5tgs_reqOptionalsNULLexceptserver",
        gokrb5_test: "messages/KDCReq_test.go",
        der_type: DerType::TgsReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "as_rep",
        gokrb5_constant: "MarshaledKRB5as_rep",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::AsRep,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "as_rep_optionals_null",
        gokrb5_constant: "MarshaledKRB5as_repOptionalsNULL",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::AsRep,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "tgs_rep",
        gokrb5_constant: "MarshaledKRB5tgs_rep",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::TgsRep,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "tgs_rep_optionals_null",
        gokrb5_constant: "MarshaledKRB5tgs_repOptionalsNULL",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::TgsRep,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_tgs_rep_part",
        gokrb5_constant: "MarshaledKRB5enc_kdc_rep_part",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::EncTgsRepPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_tgs_rep_part_optionals_null",
        gokrb5_constant: "MarshaledKRB5enc_kdc_rep_partOptionalsNULL",
        gokrb5_test: "messages/KDCRep_test.go",
        der_type: DerType::EncTgsRepPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "ap_req",
        gokrb5_constant: "MarshaledKRB5ap_req",
        gokrb5_test: "messages/APReq_test.go",
        der_type: DerType::ApReq,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "ap_rep",
        gokrb5_constant: "MarshaledKRB5ap_rep",
        gokrb5_test: "messages/APRep_test.go",
        der_type: DerType::ApRep,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_ap_rep_part",
        gokrb5_constant: "MarshaledKRB5ap_rep_enc_part",
        gokrb5_test: "messages/APRep_test.go",
        der_type: DerType::EncApRepPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_ap_rep_part_optionals_null",
        gokrb5_constant: "MarshaledKRB5ap_rep_enc_partOptionalsNULL",
        gokrb5_test: "messages/APRep_test.go",
        der_type: DerType::EncApRepPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "krb_safe",
        gokrb5_constant: "MarshaledKRB5safe",
        gokrb5_test: "messages/KRBSafe_test.go",
        der_type: DerType::KrbSafe,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "krb_safe_optionals_null",
        gokrb5_constant: "MarshaledKRB5safeOptionalsNULL",
        gokrb5_test: "messages/KRBSafe_test.go",
        der_type: DerType::KrbSafe,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "krb_priv",
        gokrb5_constant: "MarshaledKRB5priv",
        gokrb5_test: "messages/KRBPriv_test.go",
        der_type: DerType::KrbPriv,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "enc_krb_priv_part",
        gokrb5_constant: "MarshaledKRB5enc_priv_part",
        gokrb5_test: "messages/KRBPriv_test.go",
        der_type: DerType::EncKrbPrivPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "enc_krb_priv_part_optionals_null",
        gokrb5_constant: "MarshaledKRB5enc_priv_partOptionalsNULL",
        gokrb5_test: "messages/KRBPriv_test.go",
        der_type: DerType::EncKrbPrivPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "krb_cred",
        gokrb5_constant: "MarshaledKRB5cred",
        gokrb5_test: "messages/KRBCred_test.go",
        der_type: DerType::KrbCred,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "enc_krb_cred_part",
        gokrb5_constant: "MarshaledKRB5enc_cred_part",
        gokrb5_test: "messages/KRBCred_test.go",
        der_type: DerType::EncKrbCredPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "enc_krb_cred_part_optionals_null",
        gokrb5_constant: "MarshaledKRB5enc_cred_partOptionalsNULL",
        gokrb5_test: "messages/KRBCred_test.go",
        der_type: DerType::EncKrbCredPart,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "krb_error",
        gokrb5_constant: "MarshaledKRB5error",
        gokrb5_test: "messages/KRBError_test.go",
        der_type: DerType::KrbError,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "krb_error_optionals_null",
        gokrb5_constant: "MarshaledKRB5errorOptionalsNULL",
        gokrb5_test: "messages/KRBError_test.go",
        der_type: DerType::KrbError,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "authorization_data",
        gokrb5_constant: "MarshaledKRB5authorization_data",
        gokrb5_test: "types/AuthorizationData_test.go",
        der_type: DerType::AuthorizationData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "ad_kdcissued",
        gokrb5_constant: "MarshaledKRB5ad_kdcissued",
        gokrb5_test: "types/AuthorizationData_test.go",
        der_type: DerType::AdKdcIssued,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "padata_sequence",
        gokrb5_constant: "MarshaledKRB5padata_sequence",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::PaDataSequence,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "padata_sequence_empty",
        gokrb5_constant: "MarshaledKRB5padataSequenceEmpty",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::PaDataSequence,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "typed_data",
        gokrb5_constant: "MarshaledKRB5typed_data",
        gokrb5_test: "types/TypedData_test.go",
        der_type: DerType::TypedData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "pa_enc_ts_enc",
        gokrb5_constant: "MarshaledKRB5pa_enc_ts",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::PaEncTsEnc,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "pa_enc_ts_enc_no_usec",
        gokrb5_constant: "MarshaledKRB5pa_enc_tsNoUsec",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::PaEncTsEnc,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "etype_info",
        gokrb5_constant: "MarshaledKRB5etype_info",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::EtypeInfo,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "etype_info_only_1",
        gokrb5_constant: "MarshaledKRB5etype_infoOnly1",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::EtypeInfo,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "etype_info_no_info",
        gokrb5_constant: "MarshaledKRB5etype_infoNoInfo",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::EtypeInfo,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::No,
        picky_krb_roundtrip: Support::No,
    },
    Asn1Fixture {
        id: "etype_info2",
        gokrb5_constant: "MarshaledKRB5etype_info2",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::EtypeInfo2,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "etype_info2_only_1",
        gokrb5_constant: "MarshaledKRB5etype_info2Only1",
        gokrb5_test: "types/PAData_test.go",
        der_type: DerType::EtypeInfo2,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "encrypted_data",
        gokrb5_constant: "MarshaledKRB5enc_data",
        gokrb5_test: "types/Cryptosystem_test.go",
        der_type: DerType::EncryptedData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "encrypted_data_msb_set_kvno",
        gokrb5_constant: "MarshaledKRB5enc_dataMSBSetkvno",
        gokrb5_test: "types/Cryptosystem_test.go",
        der_type: DerType::EncryptedData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::No,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "encrypted_data_kvno_negative_one",
        gokrb5_constant: "MarshaledKRB5enc_dataKVNONegOne",
        gokrb5_test: "types/Cryptosystem_test.go",
        der_type: DerType::EncryptedData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::No,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
    Asn1Fixture {
        id: "change_passwd_data",
        gokrb5_constant: "MarshaledChangePasswdData",
        gokrb5_test: "kadmin/changepasswddata_test.go",
        der_type: DerType::ChangePasswdData,
        rasn_kerberos: Support::Yes,
        rasn_kerberos_roundtrip: Support::Yes,
        picky_krb: Support::Yes,
        picky_krb_roundtrip: Support::Yes,
    },
];

const RASN_KERBEROS_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "asn1",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "crypto",
        support: Support::No,
    },
    SupportByArea {
        area_id: "keytab",
        support: Support::No,
    },
    SupportByArea {
        area_id: "ccache",
        support: Support::No,
    },
    SupportByArea {
        area_id: "conf",
        support: Support::No,
    },
    SupportByArea {
        area_id: "client",
        support: Support::No,
    },
    SupportByArea {
        area_id: "service",
        support: Support::No,
    },
    SupportByArea {
        area_id: "spnego",
        support: Support::No,
    },
    SupportByArea {
        area_id: "pac",
        support: Support::No,
    },
    SupportByArea {
        area_id: "docker",
        support: Support::No,
    },
];

const PICKY_KRB_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "asn1",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "crypto",
        support: Support::No,
    },
    SupportByArea {
        area_id: "keytab",
        support: Support::No,
    },
    SupportByArea {
        area_id: "ccache",
        support: Support::No,
    },
    SupportByArea {
        area_id: "conf",
        support: Support::No,
    },
    SupportByArea {
        area_id: "client",
        support: Support::No,
    },
    SupportByArea {
        area_id: "service",
        support: Support::No,
    },
    SupportByArea {
        area_id: "spnego",
        support: Support::No,
    },
    SupportByArea {
        area_id: "pac",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "docker",
        support: Support::No,
    },
];

const SSPI_RS_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "asn1",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "crypto",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "keytab",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "ccache",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "conf",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "client",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "service",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "spnego",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "pac",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "docker",
        support: Support::Partial,
    },
];

const PARSER_ONLY_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "asn1",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "crypto",
        support: Support::No,
    },
];

const EXCLUDED_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "asn1",
        support: Support::Excluded,
    },
    SupportByArea {
        area_id: "crypto",
        support: Support::Excluded,
    },
    SupportByArea {
        area_id: "keytab",
        support: Support::Excluded,
    },
    SupportByArea {
        area_id: "ccache",
        support: Support::Excluded,
    },
    SupportByArea {
        area_id: "client",
        support: Support::Excluded,
    },
];

const KENOBI_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "client",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "spnego",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "docker",
        support: Support::Partial,
    },
];

const HTTP_LAYER_ASSESSMENT: &[SupportByArea] = &[SupportByArea {
    area_id: "spnego",
    support: Support::Partial,
}];

const SYSTEM_GSSAPI_ASSESSMENT: &[SupportByArea] = &[
    SupportByArea {
        area_id: "client",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "service",
        support: Support::Partial,
    },
    SupportByArea {
        area_id: "spnego",
        support: Support::Yes,
    },
    SupportByArea {
        area_id: "docker",
        support: Support::Partial,
    },
];

/// Candidate support across the gokrb5 v8 parity contract.
pub const ASSESSMENTS: &[CandidateAssessment] = &[
    CandidateAssessment {
        candidate: Candidate::RasnKerberos,
        support: RASN_KERBEROS_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::PickyKrb,
        support: PICKY_KRB_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::SspiRs,
        support: SSPI_RS_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::KerberosParser,
        support: PARSER_ONLY_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::Krb5Rs,
        support: &[],
    },
    CandidateAssessment {
        candidate: Candidate::KerbeirosFamily,
        support: EXCLUDED_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::Kenobi,
        support: KENOBI_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::HttpNegotiateLayers,
        support: HTTP_LAYER_ASSESSMENT,
    },
    CandidateAssessment {
        candidate: Candidate::SystemGssapiWrappers,
        support: SYSTEM_GSSAPI_ASSESSMENT,
    },
];

const RASN_KERBEROS_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Kerberos ASN.1 data types",
        support: Support::Yes,
        note: "Provides RFC 4120 types and DER encode/decode through rasn.",
    },
    Capability {
        area: "Message wrappers / exact gokrb5 DER vectors",
        support: Support::Partial,
        note: "The translated fixture matrix records decode and exact DER round-trip support across gokrb5 ASN.1 unit-test vectors.",
    },
    Capability {
        area: "Client AS/TGS exchange",
        support: Support::No,
        note: "Data types only; no authentication behavior.",
    },
    Capability {
        area: "Service AP-REQ verification",
        support: Support::No,
        note: "No replay cache, decryption, or verifier behavior.",
    },
    Capability {
        area: "SPNEGO/GSSAPI",
        support: Support::No,
        note: "No HTTP Negotiate or GSSAPI context implementation.",
    },
    Capability {
        area: "Keytab / ccache / krb5.conf / PAC",
        support: Support::No,
        note: "Out of scope for this crate.",
    },
];

const PICKY_KRB_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Kerberos ASN.1 data types",
        support: Support::Yes,
        note: "Provides Kerberos DER structures and message types.",
    },
    Capability {
        area: "Message wrappers / exact gokrb5 DER vectors",
        support: Support::Partial,
        note: "The translated fixture matrix records decode and exact DER round-trip support, with visible gaps for missing Kerberos shapes.",
    },
    Capability {
        area: "PAC",
        support: Support::Partial,
        note: "Parses PAC container data, but not the full gokrb5 PAC/NDR surface by itself.",
    },
    Capability {
        area: "Client AS/TGS exchange",
        support: Support::No,
        note: "No complete client flow.",
    },
    Capability {
        area: "Service AP-REQ verification",
        support: Support::No,
        note: "No complete verifier/replay-cache flow.",
    },
    Capability {
        area: "Keytab / ccache / krb5.conf",
        support: Support::No,
        note: "Out of scope for this crate.",
    },
];

const SSPI_RS_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Negotiate/Kerberos authentication",
        support: Support::Partial,
        note: "Mature SSPI-shaped implementation; useful for Negotiate flows.",
    },
    Capability {
        area: "Public API shape",
        support: Support::Partial,
        note: "SSPI API is not a gokrb5-style Kerberos client/service API.",
    },
    Capability {
        area: "Keytab / ccache / krb5.conf",
        support: Support::Partial,
        note: "Kerberos config exists, but gokrb5 parity needs direct verification.",
    },
    Capability {
        area: "PAC / Microsoft extensions",
        support: Support::Partial,
        note: "Strong Microsoft protocol coverage; exact PAC contract still needs tests.",
    },
    Capability {
        area: "Dependency direction",
        support: Support::Partial,
        note: "Potential dependency or collaboration target rather than a full replacement.",
    },
];

const KERBEROS_PARSER_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Kerberos ASN.1 parsing",
        support: Support::Partial,
        note: "Parses Kerberos protocol structures; not a typed DER encode/decode layer.",
    },
    Capability {
        area: "Client AS/TGS exchange",
        support: Support::No,
        note: "Parser crate only; no authentication behavior.",
    },
    Capability {
        area: "Service AP-REQ verification",
        support: Support::No,
        note: "No replay cache, decryption, keytab, or verifier behavior.",
    },
    Capability {
        area: "SPNEGO/GSSAPI",
        support: Support::No,
        note: "No HTTP Negotiate or GSSAPI context implementation.",
    },
];

const KRB5_RS_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Published implementation",
        support: Support::Excluded,
        note: "Published 0.1.0 package is placeholder-sized and README marks core RFCs as planned.",
    },
    Capability {
        area: "Client AS/TGS exchange",
        support: Support::No,
        note: "No implemented client module in the published crate.",
    },
    Capability {
        area: "GSSAPI/SPNEGO",
        support: Support::No,
        note: "No implemented GSSAPI module in the published crate.",
    },
];

const KERBEIROS_FAMILY_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Keytab / ccache / crypto / ASN.1",
        support: Support::Excluded,
        note: "Relevant primitives exist, but AGPL-3.0 licensing excludes core use.",
    },
    Capability {
        area: "Client AS/TGS exchange",
        support: Support::Excluded,
        note: "Do not depend on these crates in the core implementation without explicit isolation.",
    },
];

const KENOBI_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "HTTP Negotiate client",
        support: Support::Partial,
        note: "Cross-platform Negotiate client, but not a pure-Rust gokrb5-style Kerberos core.",
    },
    Capability {
        area: "System dependency",
        support: Support::Partial,
        note: "Uses platform-specific GSSAPI/SSPI behavior rather than portable Kerberos primitives.",
    },
    Capability {
        area: "Service AP-REQ verification",
        support: Support::No,
        note: "Client-focused; does not satisfy gokrb5 service validation or replay-cache contract.",
    },
];

const HTTP_NEGOTIATE_LAYER_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "SPNEGO HTTP middleware",
        support: Support::Partial,
        note: "Useful integration reference, but middleware is not the Kerberos implementation.",
    },
    Capability {
        area: "License posture",
        support: Support::Partial,
        note: "axum-negotiate-layer is MIT; axum-negotiate is LGPL and excluded from core use.",
    },
    Capability {
        area: "Keytab / ccache / krb5.conf / PAC",
        support: Support::No,
        note: "Out of scope for HTTP middleware crates.",
    },
];

const SYSTEM_GSSAPI_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "GSSAPI/SPNEGO",
        support: Support::Yes,
        note: "Provides safe access to system GSSAPI/SSPI behavior.",
    },
    Capability {
        area: "Pure Rust / no system dependency",
        support: Support::No,
        note: "Depends on system Kerberos/GSSAPI behavior, unlike gokrb5.",
    },
    Capability {
        area: "Keytab / ccache / krb5.conf primitives",
        support: Support::Partial,
        note: "Available through system APIs, not as portable pure Rust primitives.",
    },
];

/// Candidate reports used by the generated compatibility document.
pub const REPORTS: &[CandidateReport] = &[
    CandidateReport {
        candidate: Candidate::RasnKerberos,
        capabilities: RASN_KERBEROS_CAPABILITIES,
        recommendation: "Use as a dependency candidate for ASN.1 types, not as a replacement.",
    },
    CandidateReport {
        candidate: Candidate::PickyKrb,
        capabilities: PICKY_KRB_CAPABILITIES,
        recommendation: "Evaluate as an ASN.1/PAC dependency candidate alongside rasn-kerberos.",
    },
    CandidateReport {
        candidate: Candidate::SspiRs,
        capabilities: SSPI_RS_CAPABILITIES,
        recommendation: "Run deeper spike before deciding between contribution, facade, or new crate.",
    },
    CandidateReport {
        candidate: Candidate::KerberosParser,
        capabilities: KERBEROS_PARSER_CAPABILITIES,
        recommendation: "Useful as a parser reference, not as the base implementation.",
    },
    CandidateReport {
        candidate: Candidate::Krb5Rs,
        capabilities: KRB5_RS_CAPABILITIES,
        recommendation: "Do not use as the base implementation at this time.",
    },
    CandidateReport {
        candidate: Candidate::KerbeirosFamily,
        capabilities: KERBEIROS_FAMILY_CAPABILITIES,
        recommendation: "Exclude from the default/core implementation due to AGPL licensing.",
    },
    CandidateReport {
        candidate: Candidate::Kenobi,
        capabilities: KENOBI_CAPABILITIES,
        recommendation: "Consider only as an optional/reference Negotiate client path.",
    },
    CandidateReport {
        candidate: Candidate::HttpNegotiateLayers,
        capabilities: HTTP_NEGOTIATE_LAYER_CAPABILITIES,
        recommendation: "Treat as optional web integration references, not core Kerberos dependencies.",
    },
    CandidateReport {
        candidate: Candidate::SystemGssapiWrappers,
        capabilities: SYSTEM_GSSAPI_CAPABILITIES,
        recommendation: "Useful optional interop/reference layer, not the pure-Rust core.",
    },
];
