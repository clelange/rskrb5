use rskrb5::keytab::{EncryptionKey, Entry, Keytab, Principal};

const KEYTAB_TESTUSER1_TEST_GOKRB5: &str = "05020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200110010698c4df8e9f60e7eea5a21bf4526ad25000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001300102eb8501967a7886e1f0c63ac9be8c4a0000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001300102eb8501967a7886e1f0c63ac9be8c4a0000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee00000002000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000001000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e3000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200170010084768c373663b3bef1f6385883cf7ff00000002";

#[test]
fn parses_gokrb5_keytab_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    assert_eq!(keytab.version(), 2);
    assert_eq!(keytab.entries().len(), 12);

    let first = &keytab.entries()[0];
    assert_eq!(first.kvno, 1);
    assert_eq!(first.kvno8, 1);
    assert_eq!(first.timestamp, 1_505_669_592);
    assert_eq!(first.key.etype, 17);
    assert_eq!(
        encode_hex(&first.key.value),
        "698c4df8e9f60e7eea5a21bf4526ad25"
    );
    assert_eq!(first.principal.realm, "TEST.GOKRB5");
    assert_eq!(first.principal.components, ["testuser1"]);
    assert_eq!(first.principal.name_type, 1);
}

#[test]
fn roundtrips_gokrb5_keytab_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");
    assert_eq!(keytab.to_bytes().expect("keytab serializes"), bytes);
}

#[test]
fn finds_matching_key_by_principal_kvno_and_etype() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    let (key, kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 18)
        .expect("matching key exists");
    assert_eq!(kvno, 2);
    assert_eq!(key.etype, 18);
    assert_eq!(
        encode_hex(&key.value),
        "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"
    );

    assert!(
        keytab
            .find_key(&["testuser2"], "TEST.GOKRB5", 0, 18)
            .is_err()
    );
}

#[test]
fn finds_rc4_hmac_and_des3_keys_from_gokrb5_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    let (des3_key, des3_kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 16)
        .expect("DES3 key exists");
    assert_eq!(des3_kvno, 2);
    assert_eq!(des3_key.etype, 16);
    assert_eq!(
        encode_hex(&des3_key.value),
        "4580fb91760dabe6f808c22c26494f644cb35d61d32c79e3"
    );

    let (rc4_key, rc4_kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 23)
        .expect("RC4-HMAC key exists");
    assert_eq!(rc4_kvno, 2);
    assert_eq!(rc4_key.etype, 23);
    assert_eq!(
        encode_hex(&rc4_key.value),
        "084768c373663b3bef1f6385883cf7ff"
    );
}

#[test]
fn kvno_zero_selects_newest_matching_key() {
    let mut keytab = Keytab::new();
    keytab.entries_mut().extend([
        synthetic_entry("HTTP", 1, 18, 100),
        synthetic_entry("HTTP", 2, 18, 200),
        synthetic_entry("HTTP", 3, 18, 150),
        synthetic_entry("HTTP", 4, 17, 300),
    ]);

    let (_, kvno) = keytab
        .find_key(&["HTTP"], "TEST.GOKRB5", 0, 18)
        .expect("newest matching key exists");
    assert_eq!(kvno, 2);
}

#[test]
fn rejects_invalid_keytab_inputs() {
    assert!(Keytab::parse(&[]).is_err());
    assert!(Keytab::parse(&[5]).is_err());
    assert!(Keytab::parse(&[4, 2]).is_err());
    assert!(Keytab::parse(&[5, 9]).is_err());
    assert!(Keytab::parse(&[5, 2, 0, 0, 0, 16]).is_err());
}

fn synthetic_entry(component: &str, kvno: u32, etype: i32, timestamp: u32) -> Entry {
    Entry {
        principal: Principal {
            realm: "TEST.GOKRB5".to_owned(),
            components: vec![component.to_owned()],
            name_type: 1,
        },
        timestamp,
        kvno8: kvno as u8,
        key: EncryptionKey {
            etype,
            value: vec![kvno as u8; 4],
        },
        kvno,
    }
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
