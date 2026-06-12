#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::ap_rep::{
    AP_REP_ENCPART_USAGE, Error, KRB_AP_REP_MSG_TYPE, build_ap_rep, build_ap_rep_with_confounder,
    decode_ap_rep, decode_enc_ap_rep_part, decrypt_ap_rep_enc_part, encode_ap_rep,
    encode_build_ap_rep_with_confounder,
};
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::EncryptionKey;

const MARSHALLED_AP_REP: &str = concat!(
    "6F333031A003020105A10302010FA2253023A003020100A103020105A217",
    "04156B726241534E2E312074657374206D657373616765",
);
const MARSHALLED_ENC_AP_REP_PART: &str = concat!(
    "7B363034A011180F31393934303631303036303331375AA105020301E240",
    "A2133011A003020101A10A04083132333435363738A303020111",
);
const MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL: &str =
    "7B1C301AA011180F31393934303631303036303331375AA105020301E240";
const TEST_TIME_SECONDS: i64 = 771_228_197;
const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

#[test]
fn decodes_gokrb5_ap_rep_fixture() {
    let bytes = decode_hex(MARSHALLED_AP_REP);

    let ap_rep = decode_ap_rep(&bytes).expect("AP-REP decodes");

    assert_eq!(ap_rep.pvno, Integer::from(5));
    assert_eq!(ap_rep.msg_type, Integer::from(KRB_AP_REP_MSG_TYPE));
    assert_eq!(ap_rep.enc_part.etype, 0);
    assert_eq!(ap_rep.enc_part.kvno, Some(5));
    assert_eq!(ap_rep.enc_part.cipher.as_ref(), b"krbASN.1 test message");
    assert_eq!(encode_ap_rep(&ap_rep).expect("AP-REP encodes"), bytes);
}

#[test]
fn decodes_gokrb5_enc_ap_rep_part_fixture() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART))
        .expect("EncAPRepPart decodes");

    assert_eq!(enc_part.ctime.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(enc_part.cusec, Integer::from(123_456));
    let subkey = enc_part.subkey.as_ref().expect("subkey");
    assert_eq!(subkey.r#type, 1);
    assert_eq!(subkey.value.as_ref(), b"12345678");
    assert_eq!(enc_part.seq_number, Some(17));
}

#[test]
fn decodes_gokrb5_enc_ap_rep_part_optionals_null_fixture() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL))
        .expect("EncAPRepPart decodes");

    assert_eq!(enc_part.ctime.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(enc_part.cusec, Integer::from(123_456));
    assert!(enc_part.subkey.is_none());
    assert!(enc_part.seq_number.is_none());
}

#[test]
fn builds_and_decrypts_ap_rep_with_explicit_confounder() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART))
        .expect("EncAPRepPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x55; etype.confounder_len()];

    let ap_rep =
        build_ap_rep_with_confounder(&enc_part, &key, Some(7), &confounder).expect("AP-REP builds");

    assert_eq!(ap_rep.pvno, Integer::from(5));
    assert_eq!(ap_rep.msg_type, Integer::from(KRB_AP_REP_MSG_TYPE));
    assert_eq!(ap_rep.enc_part.etype, key.etype);
    assert_eq!(ap_rep.enc_part.kvno, Some(7));
    let decrypted = decrypt_ap_rep_enc_part(&ap_rep, &key).expect("AP-REP decrypts");
    assert_eq!(decrypted, enc_part);
}

#[test]
fn encodes_built_ap_rep_with_explicit_confounder() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL))
        .expect("EncAPRepPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x33; etype.confounder_len()];

    let encoded = encode_build_ap_rep_with_confounder(&enc_part, &key, None, &confounder)
        .expect("AP-REP encodes");
    let decoded = decode_ap_rep(&encoded).expect("encoded AP-REP decodes");

    assert_eq!(decoded.enc_part.etype, key.etype);
    assert!(decoded.enc_part.kvno.is_none());
    let decrypted = decrypt_ap_rep_enc_part(&decoded, &key).expect("AP-REP decrypts");
    assert_eq!(decrypted, enc_part);
}

#[test]
fn builds_and_decrypts_ap_rep_with_random_confounder() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART))
        .expect("EncAPRepPart decodes");
    let key = reply_key();

    let ap_rep = build_ap_rep(&enc_part, &key, None).expect("AP-REP builds");

    assert_eq!(ap_rep.enc_part.etype, key.etype);
    let decrypted = decrypt_ap_rep_enc_part(&ap_rep, &key).expect("AP-REP decrypts");
    assert_eq!(decrypted, enc_part);
}

#[test]
fn rejects_ap_rep_key_etype_mismatch() {
    let enc_part = decode_enc_ap_rep_part(&decode_hex(MARSHALLED_ENC_AP_REP_PART))
        .expect("EncAPRepPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x55; etype.confounder_len()];
    let ap_rep =
        build_ap_rep_with_confounder(&enc_part, &key, None, &confounder).expect("AP-REP builds");
    let wrong_key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error =
        decrypt_ap_rep_enc_part(&ap_rep, &wrong_key).expect_err("wrong etype key is rejected");

    assert!(matches!(
        error,
        Error::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        }
    ));
}

#[test]
fn exposes_ap_rep_key_usage_constant() {
    assert_eq!(AP_REP_ENCPART_USAGE, 12);
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
