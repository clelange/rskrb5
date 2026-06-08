use std::time::Duration;

use pretty_assertions::assert_eq;
use rskrb5::config::{Config, Error, parse_duration};

const KRB5_CONF: &str = r#"[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  kdc = 127.0.0.2:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }
 RESDOM.GOKRB5 = {
  kdc = 10.80.88.88:188
  admin_server = 127.0.0.1:749
  default_domain = resdom.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 .resdom.gokrb5 = RESDOM.GOKRB5
 resdom.gokrb5 = RESDOM.GOKRB5
 "#;

const COMPLEX_KRB5_CONF: &str = r#"
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log

[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false
 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored
  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88
  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
	lowercase.org = {
		kdc = kerberos.lowercase.org
		admin_server = kerberos.lowercase.org
	}

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored
 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored
 .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org

[appdefaults]
 pam = {
   debug = false
 }
"#;

#[test]
fn parses_gokrb5_integration_config_fixture() {
    let config = Config::parse(KRB5_CONF).expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert!(!config.libdefaults.dns_lookup_realm);
    assert!(!config.libdefaults.dns_lookup_kdc);
    assert!(!config.libdefaults.no_addresses);
    assert!(config.libdefaults.forwardable);
    assert_eq!(
        config.libdefaults.ticket_lifetime,
        Duration::from_secs(24 * 60 * 60)
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [18]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [18]);

    assert_eq!(config.realms.len(), 2);
    assert_eq!(
        config.configured_kdcs("TEST.GOKRB5").expect("KDCs exist"),
        ["127.0.0.1:88", "127.0.0.2:88"]
    );
    assert_eq!(
        config
            .configured_kpasswd_servers("TEST.GOKRB5")
            .expect("kpasswd servers default from admin_server"),
        ["127.0.0.1:464"]
    );
    assert_eq!(
        config.resolve_realm("host.test.gokrb5"),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.resolve_realm("resdom.gokrb5."),
        Some("RESDOM.GOKRB5")
    );
}

#[test]
fn parses_complex_gokrb5_config_semantics() {
    let config = Config::parse(COMPLEX_KRB5_CONF).expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert_eq!(
        config.libdefaults.ticket_lifetime,
        Duration::from_secs(10 * 60 * 60)
    );
    assert_eq!(
        config.libdefaults.default_keytab_name,
        "FILE:/etc/krb5.keytab"
    );
    assert_eq!(
        config.libdefaults.default_client_keytab_name,
        "FILE:/home/gokrb5/client.keytab"
    );
    assert_eq!(
        config.libdefaults.default_tkt_enctypes,
        ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [18, 17]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [18, 17, 23]);

    assert_eq!(config.realms.len(), 3);
    let test_realm = config.realm("TEST.GOKRB5").expect("TEST realm exists");
    assert_eq!(test_realm.realm, "TEST.GOKRB5");
    assert_eq!(test_realm.admin_server, ["10.80.88.88:749"]);
    assert_eq!(test_realm.kpasswd_server, ["10.80.88.88:464"]);
    assert_eq!(test_realm.default_domain, "test.gokrb5");
    assert_eq!(
        test_realm.kdc,
        [
            "10.80.88.88:88",
            "assume.port.num:88",
            "some.other.port:1234",
            "10.80.88.88:88"
        ]
    );

    let example = config.realm("EXAMPLE.COM").expect("example realm exists");
    assert_eq!(
        example.kdc,
        ["kerberos.example.com:88", "kerberos-1.example.com:88"]
    );
    assert_eq!(example.admin_server, ["kerberos.example.com"]);
    assert_eq!(example.kpasswd_server, ["kerberos.example.com:464"]);

    assert_eq!(
        config.domain_realm.get(".test.gokrb5").map(String::as_str),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.domain_realm.get("test.gokrb5").map(String::as_str),
        Some("TEST.GOKRB5")
    );
}

#[test]
fn duration_formats_match_gokrb5() {
    let cases = [
        ("100", Duration::from_secs(100)),
        ("12:30", Duration::from_secs(12 * 60 * 60 + 30 * 60)),
        ("12:30:15", Duration::from_secs(12 * 60 * 60 + 30 * 60 + 15)),
        (
            "1d12h30m15s",
            Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60 + 30 * 60 + 15),
        ),
        (
            "1d12h30m",
            Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60 + 30 * 60),
        ),
        ("1d12h", Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60)),
        ("1d", Duration::from_secs(24 * 60 * 60)),
    ];

    for (input, expected) in cases {
        assert_eq!(parse_duration(input).expect("duration parses"), expected);
    }
}

#[test]
fn resolve_realm_matches_gokrb5_specificity() {
    let config = Config::parse(COMPLEX_KRB5_CONF).expect("config parses");

    assert_eq!(config.resolve_realm("unknown.com"), None);
    assert_eq!(
        config.resolve_realm("hostname1.example.com"),
        Some("EXAMPLE.COM")
    );
    assert_eq!(
        config.resolve_realm("hostname2.example.com"),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.resolve_realm("one.two.three.example.com"),
        Some("EXAMPLE.COM")
    );
    assert_eq!(config.resolve_realm(".test.gokrb5"), Some("TEST.GOKRB5"));
    assert_eq!(
        config.resolve_realm("foo.testlowercase.org"),
        Some("lowercase.org")
    );
}

#[test]
fn configured_kdcs_are_used_even_when_dns_lookup_is_enabled() {
    let config = Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
"#,
    )
    .expect("config parses");

    assert!(config.libdefaults.dns_lookup_kdc);
    assert_eq!(
        config.configured_kdcs("TEST.GOKRB5").expect("KDCs exist"),
        ["kdc2b.test.gokrb5:88"]
    );
}

#[test]
fn libdefaults_keys_are_case_insensitive_and_extra_addresses_are_comma_separated() {
    let config = Config::parse(
        r#"
[libdefaults]
 DEFAULT_REALM = TEST.GOKRB5
 EXTRA_ADDRESSES = 127.0.0.1, 127.0.0.2, not-an-ip
 FORWARDABLE = TRUE
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert!(config.libdefaults.forwardable);
    assert_eq!(config.libdefaults.extra_addresses.len(), 2);
    assert_eq!(
        config.libdefaults.extra_addresses[0].to_string(),
        "127.0.0.1"
    );
    assert_eq!(
        config.libdefaults.extra_addresses[1].to_string(),
        "127.0.0.2"
    );
}

#[test]
fn maps_rc4_hmac_enctype_aliases() {
    let config = Config::parse(
        r#"
[libdefaults]
 default_tkt_enctypes = arcfour-hmac rc4-hmac arcfour-hmac-md5
 default_tgs_enctypes = rc4-hmac
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [23, 23, 23]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [23]);
}

#[test]
fn rejects_v4_realm_directives() {
    let err = Config::parse(
        r#"
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  v4_name_convert = {
   host = {
    rcmd = host
   }
  }
 }
"#,
    )
    .expect_err("v4 directives are rejected");

    assert!(matches!(err, Error::UnsupportedDirective(_)));
}
