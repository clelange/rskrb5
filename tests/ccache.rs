use pretty_assertions::assert_eq;
use rskrb5::ccache::{CCache, CacheName, Credential, Error, Principal};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

const CCACHE_TEST: &str = concat!(
    "0504000c00010008000000060000000000000001000000010000000b544553542e474f4b524235000000097465737475",
    "7365723100000001000000010000000b544553542e474f4b524235000000097465737475736572310000000200000002",
    "0000000b544553542e474f4b524235000000066b72627467740000000b544553542e474f4b52423500120000002088b9",
    "4319f2dcd1de20ebd3bf3174778769323bce76ef71fb37a8ba4be93c38df59665b8e59665b8e5967044e5967ad080040",
    "c1000000000000000000000000015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea0",
    "03020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a2",
    "82010604820102ee32bb7e27ad6f71869be098c4002b291f370d26302c87ffa3eb670345a11fc113a9e5ab9e26ea6591",
    "04b29e2a60c07dda559654c58aaf5f48bbb3bb9a238745861be336a0672554dac9b38126b2929ce9df2add185d1043c6",
    "dd89c7308b9def7b98ba7bcdcd1c00eeb5d99e273e1fe53b88c057106ec3dbcf2a86c38a4c1372418f1afb0227975747",
    "edf2172e23716ab5f6fa9a2ee5c0d94e9f66936df767498677861926812d1f887de6f44e5ebd93b63fd8313a499372ea",
    "9e889620bd0842bc8a8f8a17e5dea328c77b771cfcd49ac7afa4a9c7236efa30fec1b2072255543aee48cd935ece367e",
    "08d24f51bea4b407ace8ed7e67a8d5e1cb528eb16c7ebe7ac50000000000000001000000010000000b544553542e474f",
    "4b5242350000000974657374757365723100000000000000030000000c582d4341434845434f4e463a000000156b7262",
    "355f6363616368655f636f6e665f646174610000000a666173745f617661696c0000001e6b72627467742f544553542e",
    "474f4b52423540544553542e474f4b524235000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000037965730000000000000001000000010000000b544553542e474f4b524235000000097465737475",
    "7365723100000001000000020000000b544553542e474f4b524235000000044854545000000010686f73742e74657374",
    "2e676f6b726235001200000020fd325da3f905d743894e828de41b21af7876b6281b66d9e4bb2eefd64078b47659665b",
    "8e59665bce5967044e5967ad0800408900000000000000000000000001706182016c30820168a003020105a10d1b0b54",
    "4553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a3",
    "82012b30820127a003020112a103020101a282011904820115ad55d79858ce41647e835769b40540bc32ff4debe10121",
    "7a7a024016697ee5ff758829940ca576905a260732c43c2996d96b83f9bff010fdbfc8f3bff51cef202a956f8d73d18c",
    "2c8865553f55229075270f42dca23d7618ff35e578a972d40746398efd478cf4f1094d99371273b3fbe5b95707011b44",
    "6ff605ea8cb0e6631ea0ffdd7b562b5aa2de5dd455388e1aa18d8a3a8e81dab058e1b223410a752e5ec82797164dabaf",
    "dbec8eeef7b072304e46d7d15b575f44cce69a368a9004612ba179b41d4655964933f7eb114a457aa1127291fc6d63de",
    "b271e5504de6fccca33260645ef5bd1ea301d74a8dbf751aa181ed92f5edb493d68222e1a34892035b88b6fb0ce104db",
    "23f7da22a8e73359d9c322b8e1cc00000000"
);

#[test]
fn parses_gokrb5_ccache_fixture() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");

    assert_eq!(cache.version(), 4);
    assert_eq!(cache.header().fields.len(), 1);
    assert_eq!(cache.header().fields[0].tag, 1);
    assert_eq!(cache.header().fields[0].value.len(), 8);
    assert_eq!(cache.default_principal().realm, "TEST.GOKRB5");
    assert_eq!(cache.default_principal().name_type, 1);
    assert_eq!(cache.default_principal().components, ["testuser1"]);
    assert_eq!(cache.client_realm(), "TEST.GOKRB5");
    assert_eq!(cache.client_name(), "testuser1");
    assert_eq!(cache.credentials().len(), 3);

    assert!(cache.contains_server(&["krbtgt", "TEST.GOKRB5"]));
    assert!(cache.contains_server(&["HTTP", "host.test.gokrb5"]));
}

#[test]
fn roundtrips_gokrb5_ccache_fixture() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    assert_eq!(cache.to_bytes().expect("ccache serializes"), bytes);
}

#[test]
fn saves_and_loads_ccache_file() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let path = temp_file("save-load");

    cache.save(&path).expect("ccache saves");
    let loaded = CCache::load(&path).expect("ccache loads");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded, cache);
}

#[test]
fn saves_and_loads_ccache_from_env() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let path = temp_file("save-load-env");
    let name = format!("FILE:{}", path.display());
    let _env = common::EnvVarGuard::set_krb5ccname(&name);

    cache.save_to_env().expect("ccache saves to env name");
    let loaded = CCache::load_from_env().expect("ccache loads from env name");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded, cache);
}

#[test]
fn rejects_missing_ccache_env_name() {
    let _env = common::EnvVarGuard::remove_krb5ccname();

    assert!(matches!(
        CCache::load_from_env().expect_err("missing KRB5CCNAME rejected on load"),
        Error::DefaultCacheName(std::env::VarError::NotPresent)
    ));
    assert!(matches!(
        CCache::new(Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ))
        .save_to_env()
        .expect_err("missing KRB5CCNAME rejected on save"),
        Error::DefaultCacheName(std::env::VarError::NotPresent)
    ));
}

#[test]
fn resolves_file_cache_names() {
    assert_eq!(
        CCache::file_path_from_cache_name("/tmp/krb5cc_1000").expect("bare path resolves"),
        PathBuf::from("/tmp/krb5cc_1000")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("FILE:/tmp/krb5cc_1000").expect("FILE path resolves"),
        PathBuf::from("/tmp/krb5cc_1000")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("file:/tmp/krb5cc_1000")
            .expect("lowercase FILE path resolves"),
        PathBuf::from("/tmp/krb5cc_1000")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("WRFILE:relative-cache").expect("WRFILE path resolves"),
        PathBuf::from("relative-cache")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("DIR::/run/user/1000/krb5cc/tktABC")
            .expect("DIR subsidiary path resolves"),
        PathBuf::from("/run/user/1000/krb5cc/tktABC")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("dir::relative/tktABC")
            .expect("lowercase DIR subsidiary path resolves"),
        PathBuf::from("relative/tktABC")
    );
    assert_eq!(
        CCache::file_path_from_cache_name("C:\\temp\\krb5cc").expect("Windows path resolves"),
        PathBuf::from("C:\\temp\\krb5cc")
    );

    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_owned());
    assert_eq!(
        CCache::file_path_from_cache_name("FILE:/tmp/krb5cc_%{uid}")
            .expect("uid path token resolves"),
        PathBuf::from(format!("/tmp/krb5cc_{uid}"))
    );
    assert_eq!(
        CCache::file_path_from_cache_name("WRFILE:/tmp/krb5cc_%{euid}")
            .expect("euid path token resolves"),
        PathBuf::from(format!("/tmp/krb5cc_{uid}"))
    );
    assert_eq!(
        CCache::file_path_from_cache_name("DIR::relative/tkt_%{uid}")
            .expect("DIR subsidiary uid path token resolves"),
        PathBuf::from(format!("relative/tkt_{uid}"))
    );
}

#[test]
fn parses_typed_file_cache_names() {
    let parsed = CacheName::parse("FILE:/tmp/krb5cc_1000").expect("FILE cache name parses");
    assert_eq!(parsed.file_path(), PathBuf::from("/tmp/krb5cc_1000"));
    assert_eq!(parsed.into_file_path(), PathBuf::from("/tmp/krb5cc_1000"));

    let parsed: CacheName = "WRFILE:relative-cache"
        .parse()
        .expect("WRFILE cache name parses through FromStr");
    assert_eq!(parsed.file_path(), PathBuf::from("relative-cache"));

    let parsed = CacheName::parse("DIR::relative/tktABC").expect("DIR subsidiary name parses");
    assert_eq!(parsed.file_path(), PathBuf::from("relative/tktABC"));

    assert!(matches!(
        CacheName::parse("DIR:relative-collection")
            .expect_err("DIR primary collection needs ccache resolution"),
        Error::UnsupportedCacheType { cache_type } if cache_type == "DIR"
    ));

    let parsed = CacheName::parse("C:\\temp\\krb5cc").expect("Windows path parses");
    assert_eq!(parsed.file_path(), PathBuf::from("C:\\temp\\krb5cc"));
}

#[test]
fn rejects_unsupported_cache_names() {
    assert!(matches!(
        CCache::file_path_from_cache_name("").expect_err("empty name rejected"),
        Error::InvalidCacheName
    ));
    assert!(matches!(
        CCache::file_path_from_cache_name("FILE:").expect_err("empty FILE path rejected"),
        Error::InvalidCacheName
    ));
    assert!(matches!(
        CCache::file_path_from_cache_name("DIR:").expect_err("empty DIR collection rejected"),
        Error::InvalidCacheName
    ));
    assert!(matches!(
        CCache::file_path_from_cache_name("DIR::").expect_err("empty DIR subsidiary rejected"),
        Error::InvalidCacheName
    ));
    assert!(matches!(
        CCache::file_path_from_cache_name("DIR::tktABC")
            .expect_err("DIR subsidiary without parent rejected"),
        Error::InvalidCacheName
    ));
    assert!(matches!(
        CCache::file_path_from_cache_name("DIR::relative/not-cache")
            .expect_err("DIR subsidiary filename rejected"),
        Error::InvalidCacheName
    ));
    for cache_name in ["API:", "KCM:", "KEYRING:", "MSLSA:"] {
        let expected_type = cache_name.trim_end_matches(':');
        assert!(
            matches!(
                CCache::file_path_from_cache_name(cache_name)
                    .expect_err("unsupported cache rejected"),
                Error::UnsupportedCacheType { cache_type } if cache_type == expected_type
            ),
            "{cache_name}"
        );
    }
}

#[test]
fn encryption_key_debug_redacts_value() {
    let key = rskrb5::ccache::EncryptionKey {
        etype: 18,
        value: vec![1, 2, 3, 4],
    };
    let debug = format!("{key:?}");

    assert_eq!(debug, "EncryptionKey { etype: 18, value_len: 4 }");
    assert!(!debug.contains("1, 2, 3, 4"));
}

#[cfg(feature = "serde")]
#[test]
fn ccache_metadata_json_redacts_key_and_ticket_values() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache parses");
    let metadata = cache.credential_metadata();

    assert_eq!(metadata.len(), 3);
    assert_eq!(metadata[0].client, "testuser1@TEST.GOKRB5");
    assert_eq!(metadata[0].server, "krbtgt/TEST.GOKRB5@TEST.GOKRB5");
    assert_eq!(metadata[0].etype, 18);
    assert_eq!(metadata[0].key_length, 32);
    assert_eq!(metadata[0].ticket_length, 346);
    assert!(metadata[1].is_config_entry);

    let json = cache.credentials_json().expect("ccache JSON renders");
    assert!(json.contains(r#""Server": "HTTP/host.test.gokrb5@TEST.GOKRB5""#));
    assert!(json.contains(r#""KeyLength": 32"#));
    assert!(json.contains(r#""TicketLength": 368"#));
    assert!(
        !json.contains("88b94319f2dcd1de20ebd3bf3174778769323bce76ef71fb37a8ba4be93c38df"),
        "raw key material is not rendered"
    );
    assert!(
        !json.contains("6182015630820152a003020105"),
        "ticket DER is not rendered"
    );
}

#[test]
fn saves_and_loads_file_cache_name() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let path = temp_file("save-load-name");
    let name = format!("FILE:{}", path.display());

    cache.save_name(&name).expect("ccache saves by name");
    let loaded = CCache::load_name(&name).expect("ccache loads by name");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded, cache);
}

#[test]
fn saves_and_loads_dir_subsidiary_cache_name() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let directory = temp_dir("save-load-dir-subsidiary");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    let path = directory.join("tktABC");
    let name = format!("DIR::{}", path.display());

    cache
        .save_name(&name)
        .expect("ccache saves by DIR subsidiary name");
    let loaded = CCache::load_name(&name).expect("ccache loads by DIR subsidiary name");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&directory);

    assert_eq!(loaded, cache);
}

#[test]
fn saves_and_loads_dir_primary_collection_cache_name() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let directory = temp_dir("save-load-dir-primary");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    let name = format!("DIR:{}", directory.display());

    cache
        .save_name(&name)
        .expect("ccache saves by DIR primary collection name");
    assert_eq!(
        std::fs::read_to_string(directory.join("primary")).expect("primary file is written"),
        "tkt\n"
    );
    let loaded = CCache::load_name(&name).expect("ccache loads by DIR primary collection name");
    assert_eq!(loaded, cache);

    let _ = std::fs::remove_file(directory.join("tkt"));
    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);
}

#[test]
fn dir_primary_collection_uses_existing_primary_file() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let directory = temp_dir("existing-dir-primary");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    std::fs::write(directory.join("primary"), b"tktABC\n").expect("primary file is written");
    let name = format!("DIR:{}", directory.display());

    cache
        .save_name(&name)
        .expect("ccache saves to existing DIR primary");
    assert!(directory.join("tktABC").exists());
    let loaded = CCache::load_name(&name).expect("ccache loads existing DIR primary");
    assert_eq!(loaded, cache);

    let _ = std::fs::remove_file(directory.join("tktABC"));
    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);
}

#[test]
fn dir_primary_collection_rejects_invalid_primary_file() {
    let directory = temp_dir("invalid-dir-primary");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    std::fs::write(directory.join("primary"), b"not-a-cache\n").expect("primary file is written");
    let name = format!("DIR:{}", directory.display());

    assert!(matches!(
        CCache::file_path_from_cache_name(&name).expect_err("invalid primary file rejected"),
        Error::InvalidCacheName
    ));

    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);
}

#[test]
fn gets_client_and_server_entries() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");

    let entry = cache
        .get_entry(&["HTTP", "host.test.gokrb5"])
        .expect("HTTP service entry exists");
    assert_eq!(entry.server.realm, "TEST.GOKRB5");
    assert_eq!(entry.server.name_type, 1);
    assert_eq!(entry.server.name_string(), "HTTP/host.test.gokrb5");
    assert_eq!(entry.client.realm, "TEST.GOKRB5");
    assert_eq!(entry.client.name_string(), "testuser1");
    assert_eq!(entry.key.etype, 18);
    assert_eq!(entry.key.value.len(), 32);
    assert_eq!(entry.ticket_flags, [0x40, 0x89, 0x00, 0x00]);
    assert_eq!(entry.addresses.len(), 0);
    assert_eq!(entry.auth_data.len(), 0);
    assert_eq!(entry.second_ticket.len(), 0);
}

#[test]
fn entries_filter_out_x_cacheconf_credentials() {
    let bytes = decode_hex(CCACHE_TEST);
    let cache = CCache::parse(&bytes).expect("ccache fixture parses");

    let entries = cache.entries();
    assert_eq!(entries.len(), 2);
    let config_entries = cache.config_entries();
    assert_eq!(config_entries.len(), 1);
    assert_eq!(config_entries[0].key, "fast_avail");
    assert_eq!(
        config_entries[0].principal,
        Some("krbtgt/TEST.GOKRB5@TEST.GOKRB5")
    );
    assert_eq!(config_entries[0].value, b"yes");
    assert_eq!(
        cache.config_entry_value("fast_avail", Some("krbtgt/TEST.GOKRB5@TEST.GOKRB5")),
        Some(b"yes".as_slice())
    );
    assert!(
        cache
            .config_entry_value("fast_avail", Some("krbtgt/OTHER.GOKRB5@OTHER.GOKRB5"))
            .is_none()
    );
    assert!(
        cache
            .credentials()
            .iter()
            .any(|entry| entry.server.realm.starts_with("X-CACHECONF"))
    );
}

#[test]
fn builds_and_upserts_x_cacheconf_entries() {
    let client = Principal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]);
    let credential =
        Credential::config_entry(client.clone(), "start_realm", None, b"TEST.GOKRB5".to_vec());

    assert_eq!(credential.client, client);
    assert_eq!(credential.server.realm, "X-CACHECONF:");
    assert_eq!(
        credential.server.components,
        ["krb5_ccache_conf_data", "start_realm"]
    );
    assert_eq!(credential.ticket, b"TEST.GOKRB5");
    assert_eq!(credential.key.etype, 0);
    assert!(credential.key.value.is_empty());

    let mut cache = CCache::new(credential.client.clone());
    assert!(
        cache
            .upsert_config_entry("start_realm", None, b"TEST.GOKRB5".to_vec())
            .is_none()
    );
    assert_eq!(cache.entries().len(), 0);
    assert_eq!(
        cache.config_entry_value("start_realm", None),
        Some(b"TEST.GOKRB5".as_slice())
    );

    let replaced = cache
        .upsert_config_entry("start_realm", None, b"OTHER.GOKRB5".to_vec())
        .expect("config entry is replaced");
    assert_eq!(replaced.ticket, b"TEST.GOKRB5");
    assert_eq!(
        cache.config_entry_value("start_realm", None),
        Some(b"OTHER.GOKRB5".as_slice())
    );
}

#[test]
fn upserts_and_removes_client_entries_without_dropping_config() {
    let bytes = decode_hex(CCACHE_TEST);
    let mut cache = CCache::parse(&bytes).expect("ccache fixture parses");
    let mut client = cache.default_principal().clone();
    client.name_type = 0;
    let mut replacement = cache
        .get_entry(&["HTTP", "host.test.gokrb5"])
        .expect("HTTP service entry exists")
        .clone();
    replacement.key.value = vec![1, 2, 3, 4];

    let replaced = cache.upsert_credential(replacement.clone());
    assert!(replaced.is_some());
    assert_eq!(cache.credentials().len(), 3);
    assert_eq!(
        cache
            .get_entry(&["HTTP", "host.test.gokrb5"])
            .expect("HTTP service entry still exists")
            .key
            .value,
        replacement.key.value
    );

    let removed = cache.remove_entries_for_client(&client);
    assert_eq!(removed.len(), 2);
    assert_eq!(cache.credentials().len(), 1);
    assert!(
        cache.credentials()[0]
            .server
            .realm
            .starts_with("X-CACHECONF")
    );
}

#[test]
fn rejects_invalid_ccache_inputs() {
    assert!(matches!(
        CCache::parse(&[]).expect_err("empty ccache rejected"),
        Error::TooShort { .. }
    ));
    assert!(matches!(
        CCache::parse(&[4, 4]).expect_err("first byte rejected"),
        Error::InvalidFirstByte(4)
    ));
    assert!(matches!(
        CCache::parse(&[5, 5]).expect_err("version rejected"),
        Error::InvalidVersion(5)
    ));
    assert!(matches!(
        CCache::parse(&[5, 4, 0, 12]).expect_err("truncated header rejected"),
        Error::Truncated { .. }
    ));
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]);
            let low = hex_value(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

fn temp_file(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-ccache-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn temp_dir(name: &str) -> PathBuf {
    temp_file(name)
}
