#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rskrb5::client::{Error, Principal};

#[test]
fn principal_helpers_parse_user_and_service_names() {
    assert_eq!(
        Principal::parse_user("testuser1@TEST.GOKRB5").expect("user parses"),
        Principal::user("TEST.GOKRB5", "testuser1")
    );
    assert_eq!(
        Principal::parse_user(r"user\@name@TEST.GOKRB5").expect("escaped user parses"),
        Principal::user("TEST.GOKRB5", "user@name")
    );
    assert_eq!(
        Principal::parse_user(r"user\/name@TEST.GOKRB5").expect("escaped slash parses"),
        Principal::user("TEST.GOKRB5", "user/name")
    );
    assert_eq!(
        Principal::parse_service("HTTP/host.test.gokrb5@TEST.GOKRB5").expect("service parses"),
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
    );
    assert_eq!(
        Principal::parse_service(r"HTTP/host\@name@TEST.GOKRB5").expect("escaped service parses"),
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host@name"])
    );
}

#[test]
fn principal_helpers_reject_malformed_names() {
    for value in [
        "",
        "testuser1",
        "@TEST.GOKRB5",
        "testuser1@",
        "testuser1@TEST.GOKRB5@EXTRA",
        r"testuser1\",
        "testuser1/extra@TEST.GOKRB5",
    ] {
        assert!(
            matches!(
                Principal::parse_user(value).expect_err("malformed user rejected"),
                Error::InvalidPrincipalName { .. }
            ),
            "{value:?}"
        );
    }

    for value in [
        "HTTP@TEST.GOKRB5",
        "HTTP/@TEST.GOKRB5",
        "HTTP/host.test.gokrb5@",
        "HTTP/host.test.gokrb5@TEST.GOKRB5@EXTRA",
        r"HTTP/host.test.gokrb5\",
    ] {
        assert!(
            matches!(
                Principal::parse_service(value).expect_err("malformed service rejected"),
                Error::InvalidPrincipalName { .. }
            ),
            "{value:?}"
        );
    }
}

#[test]
fn principal_helpers_create_host_based_services() {
    assert_eq!(
        Principal::host_based_service("HTTP", "auth.cern.ch").expect("host service builds"),
        Principal::new("", 2, ["HTTP", "auth.cern.ch"])
    );
    assert_eq!(
        Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "CERN.CH")
            .expect("realm service builds"),
        Principal::new("CERN.CH", 2, ["HTTP", "auth.cern.ch"])
    );
    assert!(matches!(
        Principal::host_based_service("", "auth.cern.ch").expect_err("empty service rejected"),
        Error::InvalidPrincipalName { .. }
    ));
    assert!(matches!(
        Principal::host_based_service("HTTP", "").expect_err("empty host rejected"),
        Error::InvalidPrincipalName { .. }
    ));
    assert!(matches!(
        Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "")
            .expect_err("empty realm rejected"),
        Error::InvalidPrincipalName { .. }
    ));
}
