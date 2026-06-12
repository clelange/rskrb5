#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::keytab::EncryptionKey;
use rskrb5::krb_safe::{
    Error, KRB_SAFE_CHECKSUM_USAGE, KRB_SAFE_MSG_TYPE, build_krb_safe, decode_krb_safe,
    encode_krb_safe, krb_safe_checksum, verify_krb_safe_checksum,
};

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const TEST_TIME_SECONDS: i64 = 771_228_197;
const KRB_SAFE: &str = concat!(
    "746E306CA003020105A103020114A24F304DA00A04086B72623564617461A111",
    "180F31393934303631303036303331375AA205020301E240A303020111A40F",
    "300DA003020102A106040412D00023A50F300DA003020102A106040412D",
    "00023A30F300DA003020101A106040431323334",
);
const KRB_SAFE_OPTIONALS_NULL: &str = concat!(
    "743E303CA003020105A103020114A21F301DA00A04086B72623564617461",
    "A40F300DA003020102A106040412D00023A30F300DA003020101A106",
    "040431323334",
);

#[test]
fn decodes_gokrb5_krb_safe_fixture() {
    let krb_safe = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");

    assert_eq!(krb_safe.pvno, Integer::from(5));
    assert_eq!(krb_safe.msg_type, Integer::from(KRB_SAFE_MSG_TYPE));
    assert_eq!(krb_safe.body.user_data.as_ref(), b"krb5data");
    assert_eq!(
        krb_safe
            .body
            .timestamp
            .as_ref()
            .expect("timestamp")
            .0
            .timestamp(),
        TEST_TIME_SECONDS
    );
    assert_eq!(krb_safe.body.usec, Some(Integer::from(123_456)));
    assert_eq!(krb_safe.body.seq_number, Some(17));
    assert_eq!(krb_safe.body.s_address.addr_type, 2);
    assert_eq!(
        krb_safe.body.s_address.address.as_ref(),
        decode_hex("12d00023")
    );
    assert_eq!(
        krb_safe
            .body
            .r_address
            .as_ref()
            .expect("recipient address")
            .address
            .as_ref(),
        decode_hex("12d00023")
    );
    assert_eq!(krb_safe.cksum.r#type, 1);
    assert_eq!(krb_safe.cksum.checksum.as_ref(), b"1234");
}

#[test]
fn decodes_gokrb5_krb_safe_optionals_null_fixture() {
    let krb_safe = decode_krb_safe(&decode_hex(KRB_SAFE_OPTIONALS_NULL)).expect("KRB-SAFE decodes");

    assert_eq!(krb_safe.pvno, Integer::from(5));
    assert_eq!(krb_safe.msg_type, Integer::from(KRB_SAFE_MSG_TYPE));
    assert_eq!(krb_safe.body.user_data.as_ref(), b"krb5data");
    assert!(krb_safe.body.timestamp.is_none());
    assert!(krb_safe.body.usec.is_none());
    assert!(krb_safe.body.seq_number.is_none());
    assert_eq!(krb_safe.body.s_address.addr_type, 2);
    assert_eq!(
        krb_safe.body.s_address.address.as_ref(),
        decode_hex("12d00023")
    );
    assert!(krb_safe.body.r_address.is_none());
    assert_eq!(krb_safe.cksum.r#type, 1);
    assert_eq!(krb_safe.cksum.checksum.as_ref(), b"1234");
}

#[test]
fn builds_and_verifies_krb_safe_checksum() {
    let fixture = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");
    let key = reply_key();

    let checksum = krb_safe_checksum(&fixture.body, &key).expect("checksum builds");
    let krb_safe = build_krb_safe(fixture.body, &key).expect("KRB-SAFE builds");

    assert_eq!(checksum.r#type, 16);
    assert_eq!(krb_safe.cksum, checksum);
    verify_krb_safe_checksum(&krb_safe, &key).expect("checksum verifies");
}

#[test]
fn encodes_krb_safe_roundtrip() {
    let fixture = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");
    let key = reply_key();
    let krb_safe = build_krb_safe(fixture.body, &key).expect("KRB-SAFE builds");

    let bytes = encode_krb_safe(&krb_safe).expect("KRB-SAFE encodes");
    let decoded = decode_krb_safe(&bytes).expect("encoded KRB-SAFE decodes");

    assert_eq!(decoded, krb_safe);
    verify_krb_safe_checksum(&decoded, &key).expect("checksum verifies");
}

#[test]
fn rejects_unsupported_krb_safe_checksum_type() {
    let krb_safe = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");
    let key = reply_key();

    let error = verify_krb_safe_checksum(&krb_safe, &key)
        .expect_err("unsupported fixture checksum type is rejected");

    assert!(matches!(error, Error::UnsupportedChecksumType(1)));
}

#[test]
fn rejects_krb_safe_checksum_mismatch() {
    let fixture = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");
    let key = reply_key();
    let mut krb_safe = build_krb_safe(fixture.body, &key).expect("KRB-SAFE builds");
    krb_safe.body.user_data = b"tampered".to_vec().into();

    let error =
        verify_krb_safe_checksum(&krb_safe, &key).expect_err("tampered KRB-SAFE body is rejected");

    assert!(matches!(error, Error::ChecksumMismatch));
}

#[test]
fn rejects_krb_safe_key_checksum_type_mismatch() {
    let fixture = decode_krb_safe(&decode_hex(KRB_SAFE)).expect("KRB-SAFE decodes");
    let key = reply_key();
    let krb_safe = build_krb_safe(fixture.body, &key).expect("KRB-SAFE builds");
    let wrong_etype_key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error = verify_krb_safe_checksum(&krb_safe, &wrong_etype_key)
        .expect_err("wrong key etype is rejected");

    assert!(matches!(
        error,
        Error::KeyChecksumTypeMismatch {
            key_etype: 17,
            checksum_type: 16,
        }
    ));
}

#[test]
fn exposes_krb_safe_checksum_usage_constant() {
    assert_eq!(KRB_SAFE_CHECKSUM_USAGE, 15);
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: decode_hex(REPLY_KEY),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_hex_digit(chunk[0]);
            let low = decode_hex_digit(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn decode_hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
