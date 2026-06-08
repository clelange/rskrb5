//! Candidate compatibility matrix and fixture probes.

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

/// One row in the compatibility matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Contract area from `gokrb5` v8.
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

const RASN_KERBEROS_CAPABILITIES: &[Capability] = &[
    Capability {
        area: "Kerberos ASN.1 data types",
        support: Support::Yes,
        note: "Provides RFC 4120 types and DER encode/decode through rasn.",
    },
    Capability {
        area: "Message wrappers / exact gokrb5 DER vectors",
        support: Support::Partial,
        note: "Promising; must be verified against gokrb5's full DER fixture set.",
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
        note: "Has richer Microsoft/Kerberos structs than rasn-kerberos; requires fixture parity checks.",
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

/// Render the current compatibility matrix as Markdown.
pub fn render_markdown() -> String {
    let mut out = String::from("# rskrb5 Compatibility Spike\n\n");
    out.push_str("This report is generated from `rskrb5::evaluation` and captures the decision gate before implementing a standalone Kerberos library.\n\n");

    for report in REPORTS {
        out.push_str("## ");
        out.push_str(report.candidate.name());
        out.push('\n');
        out.push('\n');
        out.push_str("- License: `");
        out.push_str(report.candidate.license());
        out.push_str("`\n");
        out.push_str("- Recommendation: ");
        out.push_str(report.recommendation);
        out.push_str("\n\n");
        out.push_str("| Area | Support | Note |\n");
        out.push_str("|---|---:|---|\n");
        for capability in report.capabilities {
            out.push_str("| ");
            out.push_str(capability.area);
            out.push_str(" | ");
            out.push_str(&capability.support.to_string());
            out.push_str(" | ");
            out.push_str(capability.note);
            out.push_str(" |\n");
        }
        out.push('\n');
    }

    out.push_str("## Decision\n\n");
    out.push_str("Create a new `rskrb5` implementation only if `sspi-rs` plus permissively licensed ASN.1 crates cannot satisfy gokrb5 v8 parity without an awkward API facade. The immediate implementation work is to translate gokrb5 fixture tests and keep measuring candidates against those tests.\n");
    out
}

/// Fixture probes that validate candidate DER support against representative
/// gokrb5 vectors. These are intentionally small; the full parity suite should
/// be translated after the decision gate.
#[cfg(test)]
mod tests {
    use super::*;

    const GOKRB5_TICKET: &str = "615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    const GOKRB5_AP_REQ: &str = "6E819D30819AA003020105A10302010EA207030500FEDCBA98A35E615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765A4253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    const GOKRB5_KRB_ERROR: &str = "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461";

    fn decode_hex(input: &str) -> Vec<u8> {
        hex::decode(input).expect("fixture hex is valid")
    }

    #[test]
    fn rasn_kerberos_decodes_representative_gokrb5_der() {
        let ticket = decode_hex(GOKRB5_TICKET);
        let ap_req = decode_hex(GOKRB5_AP_REQ);
        let krb_error = decode_hex(GOKRB5_KRB_ERROR);

        let _: rasn_kerberos::Ticket = rasn::der::decode(&ticket).expect("ticket DER");
        let _: rasn_kerberos::ApReq = rasn::der::decode(&ap_req).expect("AP-REQ DER");
        let _: rasn_kerberos::KrbError = rasn::der::decode(&krb_error).expect("KRB-ERROR DER");
    }

    #[test]
    fn picky_krb_decodes_representative_gokrb5_der() {
        let ticket = decode_hex(GOKRB5_TICKET);
        let ap_req = decode_hex(GOKRB5_AP_REQ);
        let krb_error = decode_hex(GOKRB5_KRB_ERROR);

        let _: picky_krb::data_types::Ticket =
            picky_asn1_der::from_bytes(&ticket).expect("ticket DER");
        let _: picky_krb::messages::ApReq =
            picky_asn1_der::from_bytes(&ap_req).expect("AP-REQ DER");
        let _: picky_krb::messages::KrbError =
            picky_asn1_der::from_bytes(&krb_error).expect("KRB-ERROR DER");
    }

    #[test]
    fn report_mentions_all_candidates() {
        let markdown = render_markdown();
        for report in REPORTS {
            assert!(markdown.contains(report.candidate.name()));
        }
    }
}
