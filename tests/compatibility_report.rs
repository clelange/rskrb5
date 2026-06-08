#![cfg(feature = "evaluation")]

use rskrb5::evaluation::{ASSESSMENTS, REPORTS, V8_CONTRACT, render_markdown};

#[test]
fn report_mentions_all_candidates_and_contract_areas() {
    let markdown = render_markdown();

    for report in REPORTS {
        assert!(markdown.contains(report.candidate.name()));
    }

    for area in V8_CONTRACT {
        assert!(markdown.contains(area.area));
    }
}

#[test]
fn every_assessment_covers_only_known_contract_area_ids() {
    for assessment in ASSESSMENTS {
        for support in assessment.support {
            assert!(
                V8_CONTRACT.iter().any(|area| area.id == support.area_id),
                "{} references unknown area id {}",
                assessment.candidate.name(),
                support.area_id
            );
        }
    }
}
