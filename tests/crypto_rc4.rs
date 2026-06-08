use pretty_assertions::assert_eq;
use rskrb5::crypto::{Error, KerberosEtype, Rc4HmacEtype};

#[test]
fn reports_rc4_hmac_metadata_and_dispatch() {
    let etype = Rc4HmacEtype;

    assert_eq!(Rc4HmacEtype::from_etype_id(23), Some(Rc4HmacEtype));
    assert_eq!(Rc4HmacEtype::from_etype_id(24), None);
    assert_eq!(
        Rc4HmacEtype::from_checksum_type_id(-138),
        Some(Rc4HmacEtype)
    );

    assert_eq!(etype.etype_id(), 23);
    assert_eq!(etype.checksum_type_id(), -138);
    assert_eq!(etype.key_len(), 16);
    assert_eq!(etype.confounder_len(), 8);
    assert_eq!(etype.hmac_len(), 16);
    assert_eq!(etype.default_s2kparams(), "");

    assert_eq!(
        KerberosEtype::from_etype_id(23),
        Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype))
    );
    assert_eq!(
        KerberosEtype::from_checksum_type_id(-138),
        Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype))
    );
}

#[test]
fn rc4_hmac_string_to_key_matches_gokrb5_vector() {
    let key = Rc4HmacEtype
        .string_to_key(b"foo", b"ignored-salt", "ignored-params")
        .expect("key derives");

    assert_eq!(hex_encode(&key), "ac8e657f83df82beea5d43bdaf7800cc");
}

#[test]
fn rc4_hmac_checksum_matches_gokrb5_vector() {
    let etype = Rc4HmacEtype;
    let key = decode_hex("ac8e657f83df82beea5d43bdaf7800cc");
    let checksum = etype
        .checksum(&key, b"kerberos rc4 checksum", 2)
        .expect("checksum succeeds");

    assert_eq!(hex_encode(&checksum), "97ab2d24a2a9746b2abb88e2df99578d");
    assert!(etype.verify_checksum(&key, b"kerberos rc4 checksum", &checksum, 2));
    assert!(!etype.verify_checksum(&key, b"kerberos rc4 tampered", &checksum, 2));
}

#[test]
fn rc4_hmac_message_encryption_matches_gokrb5_vector() {
    let etype = Rc4HmacEtype;
    let key = decode_hex("ac8e657f83df82beea5d43bdaf7800cc");
    let confounder = decode_hex("0001020304050607");
    let expected = decode_hex(
        "52b24c30a78833dc78994646b37f14108e7af6ecc788485cb4c3d8d536669996e6f2a7d46047ce81a766bab4",
    );

    let encrypted = etype
        .encrypt_message_with_confounder(&key, b"kerberos rc4 message", 2, &confounder)
        .expect("message encrypts");
    assert_eq!(encrypted, expected);

    let decrypted = etype
        .decrypt_message(&key, &encrypted, 2)
        .expect("message decrypts");
    assert_eq!(decrypted, b"kerberos rc4 message");

    let dispatcher = KerberosEtype::Rc4Hmac(Rc4HmacEtype);
    assert_eq!(
        dispatcher
            .decrypt_message(&key, &encrypted, 2)
            .expect("dispatcher decrypts"),
        b"kerberos rc4 message"
    );
}

#[test]
fn rc4_hmac_rejects_invalid_inputs_and_tampering() {
    let etype = Rc4HmacEtype;
    let key = decode_hex("ac8e657f83df82beea5d43bdaf7800cc");
    let confounder = decode_hex("0001020304050607");

    assert!(matches!(
        etype.encrypt_data(&key[..15], b"data"),
        Err(Error::InvalidKeyLength {
            expected: 16,
            actual: 15
        })
    ));
    assert!(matches!(
        etype.encrypt_message_with_confounder(&key, b"data", 2, &confounder[..7]),
        Err(Error::InvalidConfounderLength {
            expected: 8,
            actual: 7
        })
    ));
    assert!(matches!(
        etype.decrypt_message(&key, &[0; 23], 2),
        Err(Error::CiphertextTooShort {
            minimum: 24,
            actual: 23
        })
    ));
    assert!(matches!(
        etype.string_to_key(&[0xff], b"", ""),
        Err(Error::InvalidStringToKeySecret)
    ));

    let mut encrypted = etype
        .encrypt_message_with_confounder(&key, b"kerberos rc4 message", 2, &confounder)
        .expect("message encrypts");
    encrypted[0] ^= 1;
    assert_eq!(
        etype.decrypt_message(&key, &encrypted, 2),
        Err(Error::IntegrityCheckFailed)
    );
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
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
