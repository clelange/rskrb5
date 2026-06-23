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
    assert_eq!(
        target.get("release_date").and_then(toml::Value::as_str),
        Some("2023-02-25")
    );
    assert_eq!(
        target.get("release_url").and_then(toml::Value::as_str),
        Some("https://github.com/jcmturner/gokrb5/releases/tag/v8.4.4")
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

    let gates = manifest
        .get("gate")
        .and_then(toml::Value::as_array)
        .expect("manifest has gate array");
    assert!(!gates.is_empty(), "manifest should describe parity gates");

    let required_gates = [
        "linux-docker-mit-full",
        "linux-docker-mit-kpasswd",
        "linux-docker-dns-srv",
        "linux-docker-privileged-ccache",
        "linux-docker-http-spnego",
        "active-directory-testad",
        "http-client-wrapper",
    ];
    let allowed_gate_statuses = ["unproven", "blocked-on-lab", "missing-api"];

    let mut gate_ids = BTreeSet::new();
    for gate in gates {
        let gate = gate.as_table().expect("gate entry is a table");
        let id = gate
            .get("id")
            .and_then(toml::Value::as_str)
            .expect("gate has id");
        assert!(gate_ids.insert(id.to_owned()), "duplicate gate id {id}");

        let name = gate
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("gate has name");
        assert!(!name.is_empty(), "gate {id} should have a non-empty name");

        let status = gate
            .get("status")
            .and_then(toml::Value::as_str)
            .expect("gate has status");
        assert!(
            allowed_gate_statuses.contains(&status),
            "gate {id} has unknown status {status}"
        );

        if status != "missing-api" {
            let command = gate
                .get("command")
                .and_then(toml::Value::as_str)
                .expect("gate with executable proof has command");
            assert!(!command.is_empty(), "gate {id} command should be non-empty");
        }

        let proves = gate
            .get("proves")
            .and_then(toml::Value::as_array)
            .expect("gate has proves array");
        assert!(!proves.is_empty(), "gate {id} should list proved areas");
        for proved in proves {
            let proved = proved
                .as_str()
                .expect("gate proves entries should be strings");
            assert!(
                ids.contains(proved),
                "gate {id} proves unknown parity area {proved}"
            );
        }

        for key in ["required_for_release", "required_for_parity"] {
            gate.get(key)
                .and_then(toml::Value::as_bool)
                .unwrap_or_else(|| panic!("gate {id} has boolean {key}"));
        }

        let evidence = gate
            .get("evidence")
            .and_then(toml::Value::as_array)
            .expect("gate has evidence array");
        assert!(
            !evidence.is_empty(),
            "gate {id} should list current evidence"
        );

        let next = gate
            .get("next")
            .and_then(toml::Value::as_array)
            .expect("gate has next array");
        assert!(!next.is_empty(), "gate {id} should list next work");
    }

    for id in required_gates {
        assert!(gate_ids.contains(id), "missing required parity gate {id}");
    }
}
