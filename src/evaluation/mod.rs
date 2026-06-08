//! Candidate compatibility matrix and fixture probes.

mod data;

use std::fmt::Write as _;

pub use data::{
    ASSESSMENTS, Candidate, CandidateAssessment, CandidateReport, Capability, ContractArea,
    REPORTS, Support, SupportByArea, V8_CONTRACT,
};

/// Render the current compatibility matrix as Markdown.
pub fn render_markdown() -> String {
    let mut out = String::from("# rskrb5 Compatibility Spike\n\n");
    out.push_str("This report is generated from `rskrb5::evaluation` and captures the decision gate before implementing a standalone Kerberos library.\n\n");

    render_contract(&mut out);
    render_decision_matrix(&mut out);
    render_candidate_details(&mut out);

    out.push_str("## Decision\n\n");
    out.push_str("Create a new `rskrb5` implementation only if `sspi-rs` plus permissively licensed ASN.1 crates cannot satisfy gokrb5 v8 parity without an awkward API facade. The immediate implementation work is to translate gokrb5 fixture tests and keep measuring candidates against those tests.\n");
    out
}

fn render_contract(out: &mut String) {
    out.push_str("## gokrb5 v8 Contract\n\n");
    out.push_str("| Area | gokrb5 tests | Gate | Porting note |\n");
    out.push_str("|---|---|---|---|\n");
    for area in V8_CONTRACT {
        writeln!(
            out,
            "| {} | {} | {} | {} |",
            area.area, area.gokrb5_tests, area.gate, area.porting_note
        )
        .expect("writing to String cannot fail");
    }
    out.push('\n');
}

fn render_decision_matrix(out: &mut String) {
    out.push_str("## Candidate Decision Matrix\n\n");
    out.push_str("| Candidate |");
    for area in V8_CONTRACT {
        write!(out, " {} |", area.id).expect("writing to String cannot fail");
    }
    out.push('\n');
    out.push_str("|---|");
    for _ in V8_CONTRACT {
        out.push_str("---:|");
    }
    out.push('\n');

    for assessment in ASSESSMENTS {
        write!(out, "| {} |", assessment.candidate.name()).expect("writing to String cannot fail");
        for area in V8_CONTRACT {
            let support = assessment.support_for(area.id);
            write!(out, " {support} |").expect("writing to String cannot fail");
        }
        out.push('\n');
    }
    out.push('\n');
}

fn render_candidate_details(out: &mut String) {
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
            writeln!(
                out,
                "| {} | {} | {} |",
                capability.area, capability.support, capability.note
            )
            .expect("writing to String cannot fail");
        }
        out.push('\n');
    }
}
