use std::collections::BTreeSet;

#[test]
fn gokrb5_parity_manifest_has_expected_target_and_areas() {
    let manifest: toml::Table = include_str!("../docs/gokrb5-parity.toml")
        .parse()
        .expect("gokrb5 parity manifest is valid TOML");

    let target = manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .expect("manifest has target table");
    assert_eq!(
        target.get("module").and_then(toml::Value::as_str),
        Some("github.com/jcmturner/gokrb5/v8")
    );
    assert_eq!(
        target.get("version").and_then(toml::Value::as_str),
        Some("v8.4.4")
    );

    let areas = manifest
        .get("area")
        .and_then(toml::Value::as_array)
        .expect("manifest has area array");
    assert!(!areas.is_empty(), "manifest should describe parity areas");

    let required = [
        "config",
        "keytab",
        "ccache",
        "crypto",
        "messages",
        "kadmin-kpasswd",
        "client",
        "service",
        "gssapi-spnego",
        "pac",
        "docker-mit",
        "active-directory",
        "non-goals",
    ];
    let allowed_statuses = [
        "covered",
        "covered-with-gated-evidence",
        "covered-needs-ad-evidence",
        "partial",
        "needs-live-evidence",
        "blocked-on-lab",
        "intentionally-out-of-scope",
    ];

    let mut ids = BTreeSet::new();
    for area in areas {
        let area = area.as_table().expect("area entry is a table");
        let id = area
            .get("id")
            .and_then(toml::Value::as_str)
            .expect("area has id");
        assert!(ids.insert(id.to_owned()), "duplicate area id {id}");

        let status = area
            .get("status")
            .and_then(toml::Value::as_str)
            .expect("area has status");
        assert!(
            allowed_statuses.contains(&status),
            "area {id} has unknown status {status}"
        );

        let evidence = area
            .get("evidence")
            .and_then(toml::Value::as_array)
            .expect("area has evidence array");
        assert!(!evidence.is_empty(), "area {id} should list evidence");

        let next = area
            .get("next")
            .and_then(toml::Value::as_array)
            .expect("area has next array");
        if status != "covered" && status != "intentionally-out-of-scope" {
            assert!(
                !next.is_empty(),
                "area {id} with status {status} should list next work"
            );
        }
    }

    for id in required {
        assert!(ids.contains(id), "missing required parity area {id}");
    }
}
