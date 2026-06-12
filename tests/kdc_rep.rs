#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::crypto::KerberosEtype;
use rskrb5::kdc_rep::{
    AS_REP_ENCPART_USAGE, Error, KRB_AS_REP_MSG_TYPE, KRB_TGS_REP_MSG_TYPE,
    TGS_REP_ENCPART_SESSION_KEY_USAGE, decode_as_rep, decode_enc_kdc_rep_part, decode_tgs_rep,
    decrypt_as_rep_enc_part, decrypt_tgs_rep_enc_part, encode_as_rep, encode_enc_as_rep_part,
    encode_enc_tgs_rep_part, encode_tgs_rep, encrypt_as_rep_enc_part,
    encrypt_as_rep_enc_part_with_confounder, encrypt_tgs_rep_enc_part,
    encrypt_tgs_rep_enc_part_with_confounder,
};
use rskrb5::keytab::EncryptionKey;

const MARSHALLED_AS_REP: &str = concat!(
    "6B81EA3081E7A003020105A10302010BA22630243010A10302010DA209",
    "040770612D646174613010A10302010DA209040770612D64617461A310",
    "1B0E415448454E412E4D49542E454455A41A3018A003020101A11130",
    "0F1B066866747361691B056578747261A55E615C305AA003020105A110",
    "1B0E415448454E412E4D49542E454455A21A3018A003020101A11130",
    "0F1B066866747361691B056578747261A3253023A003020100A10302",
    "0105A21704156B726241534E2E312074657374206D657373616765A625",
    "3023A003020100A103020105A21704156B726241534E2E312074657374",
    "206D657373616765",
);
const MARSHALLED_AS_REP_OPTIONALS_NULL: &str = concat!(
    "6B81C23081BFA003020105A10302010BA3101B0E415448454E412E4D49",
    "542E454455A41A3018A003020101A111300F1B066866747361691B05",
    "6578747261A55E615C305AA003020105A1101B0E415448454E412E4D",
    "49542E454455A21A3018A003020101A111300F1B066866747361691B",
    "056578747261A3253023A003020100A103020105A21704156B726241",
    "534E2E312074657374206D657373616765A6253023A003020100A103",
    "020105A21704156B726241534E2E312074657374206D657373616765",
);
const MARSHALLED_TGS_REP: &str = concat!(
    "6D81EA3081E7A003020105A10302010DA22630243010A10302010DA209",
    "040770612D646174613010A10302010DA209040770612D64617461A310",
    "1B0E415448454E412E4D49542E454455A41A3018A003020101A11130",
    "0F1B066866747361691B056578747261A55E615C305AA003020105A110",
    "1B0E415448454E412E4D49542E454455A21A3018A003020101A11130",
    "0F1B066866747361691B056578747261A3253023A003020100A10302",
    "0105A21704156B726241534E2E312074657374206D657373616765A625",
    "3023A003020100A103020105A21704156B726241534E2E312074657374",
    "206D657373616765",
);
const MARSHALLED_TGS_REP_OPTIONALS_NULL: &str = concat!(
    "6D81C23081BFA003020105A10302010DA3101B0E415448454E412E4D49",
    "542E454455A41A3018A003020101A111300F1B066866747361691B05",
    "6578747261A55E615C305AA003020105A1101B0E415448454E412E4D",
    "49542E454455A21A3018A003020101A111300F1B066866747361691B",
    "056578747261A3253023A003020100A103020105A21704156B726241",
    "534E2E312074657374206D657373616765A6253023A003020100A103",
    "020105A21704156B726241534E2E312074657374206D657373616765",
);
const MARSHALLED_ENC_KDC_REP_PART: &str = concat!(
    "7A82010E3082010AA0133011A003020101A10A04083132333435363738",
    "A13630343018A0030201FBA111180F3139393430363130303630333137",
    "5A3018A0030201FBA111180F31393934303631303036303331375AA203",
    "02012AA311180F31393934303631303036303331375AA407030500FEDC",
    "BA98A511180F31393934303631303036303331375AA611180F31393934",
    "303631303036303331375AA711180F3139393430363130303630333137",
    "5AA811180F31393934303631303036303331375AA9101B0E415448454E",
    "412E4D49542E454455AA1A3018A003020101A111300F1B0668667473",
    "61691B056578747261AB20301E300DA003020102A106040412D00023",
    "300DA003020102A106040412D00023",
);
const MARSHALLED_ENC_KDC_REP_PART_OPTIONALS_NULL: &str = concat!(
    "7A81B23081AFA0133011A003020101A10A04083132333435363738A136",
    "30343018A0030201FBA111180F31393934303631303036303331375A30",
    "18A0030201FBA111180F31393934303631303036303331375AA2030201",
    "2AA407030500FE5CBA98A511180F31393934303631303036303331375A",
    "A711180F31393934303631303036303331375AA9101B0E415448454E41",
    "2E4D49542E454455AA1A3018A003020101A111300F1B066866747361",
    "691B056578747261",
);
const TEST_TIME_SECONDS: i64 = 771_228_197;
const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

#[test]
fn decodes_gokrb5_as_rep_fixture() {
    let bytes = decode_hex(MARSHALLED_AS_REP);

    let as_rep = decode_as_rep(&bytes).expect("AS-REP decodes");

    assert_kdc_rep_fields(&as_rep.0, KRB_AS_REP_MSG_TYPE, 2);
    assert_eq!(encode_as_rep(&as_rep).expect("AS-REP encodes"), bytes);
}

#[test]
fn decodes_gokrb5_as_rep_optionals_null_fixture() {
    let bytes = decode_hex(MARSHALLED_AS_REP_OPTIONALS_NULL);

    let as_rep = decode_as_rep(&bytes).expect("AS-REP decodes");

    assert_kdc_rep_fields(&as_rep.0, KRB_AS_REP_MSG_TYPE, 0);
    assert_eq!(encode_as_rep(&as_rep).expect("AS-REP encodes"), bytes);
}

#[test]
fn decodes_gokrb5_tgs_rep_fixture() {
    let bytes = decode_hex(MARSHALLED_TGS_REP);

    let tgs_rep = decode_tgs_rep(&bytes).expect("TGS-REP decodes");

    assert_kdc_rep_fields(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE, 2);
    assert_eq!(encode_tgs_rep(&tgs_rep).expect("TGS-REP encodes"), bytes);
}

#[test]
fn decodes_gokrb5_tgs_rep_optionals_null_fixture() {
    let bytes = decode_hex(MARSHALLED_TGS_REP_OPTIONALS_NULL);

    let tgs_rep = decode_tgs_rep(&bytes).expect("TGS-REP decodes");

    assert_kdc_rep_fields(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE, 0);
    assert_eq!(encode_tgs_rep(&tgs_rep).expect("TGS-REP encodes"), bytes);
}

#[test]
fn decodes_gokrb5_enc_kdc_rep_part_fixture() {
    let bytes = decode_hex(MARSHALLED_ENC_KDC_REP_PART);

    let enc_part = decode_enc_kdc_rep_part(&bytes).expect("EncKdcRepPart decodes");

    assert_enc_kdc_rep_part_fields(&enc_part, 0xfedc_ba98);
    assert!(enc_part.key_expiration.is_some());
    assert!(enc_part.start_time.is_some());
    assert!(enc_part.renew_till.is_some());
    assert!(enc_part.caddr.is_some());
    assert_eq!(
        encode_enc_tgs_rep_part(&enc_part).expect("EncTgsRepPart encodes"),
        bytes,
    );
}

#[test]
fn decodes_gokrb5_enc_kdc_rep_part_optionals_null_fixture() {
    let bytes = decode_hex(MARSHALLED_ENC_KDC_REP_PART_OPTIONALS_NULL);

    let enc_part = decode_enc_kdc_rep_part(&bytes).expect("EncKdcRepPart decodes");

    assert_enc_kdc_rep_part_fields(&enc_part, 0xfe5c_ba98);
    assert!(enc_part.key_expiration.is_none());
    assert!(enc_part.start_time.is_none());
    assert!(enc_part.renew_till.is_none());
    assert!(enc_part.caddr.is_none());
    assert_eq!(
        encode_enc_tgs_rep_part(&enc_part).expect("EncTgsRepPart encodes"),
        bytes,
    );
}

#[test]
fn generic_enc_kdc_rep_decode_accepts_as_rep_application_tag() {
    let enc_part = decode_enc_kdc_rep_part(&decode_hex(MARSHALLED_ENC_KDC_REP_PART))
        .expect("EncKdcRepPart decodes");
    let encoded_as = encode_enc_as_rep_part(&enc_part).expect("EncAsRepPart encodes");

    let decoded = decode_enc_kdc_rep_part(&encoded_as).expect("EncAsRepPart decodes");

    assert_eq!(decoded, enc_part);
}

#[test]
fn builds_and_decrypts_as_rep_enc_part_with_explicit_confounder() {
    let enc_part = decode_enc_kdc_rep_part(&decode_hex(MARSHALLED_ENC_KDC_REP_PART))
        .expect("EncKdcRepPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x22; etype.confounder_len()];
    let mut as_rep = decode_as_rep(&decode_hex(MARSHALLED_AS_REP)).expect("AS-REP fixture decodes");

    as_rep.0.enc_part =
        encrypt_as_rep_enc_part_with_confounder(&enc_part, &key, Some(6), &confounder)
            .expect("AS-REP encrypted part encrypts");

    assert_eq!(as_rep.0.enc_part.etype, key.etype);
    assert_eq!(as_rep.0.enc_part.kvno, Some(6));
    let decrypted = decrypt_as_rep_enc_part(&as_rep, &key).expect("AS-REP encrypted part decrypts");
    assert_eq!(decrypted, enc_part);
}

#[test]
fn builds_and_decrypts_tgs_rep_enc_part_with_explicit_confounder() {
    let enc_part = decode_enc_kdc_rep_part(&decode_hex(MARSHALLED_ENC_KDC_REP_PART))
        .expect("EncKdcRepPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x44; etype.confounder_len()];
    let mut tgs_rep =
        decode_tgs_rep(&decode_hex(MARSHALLED_TGS_REP)).expect("TGS-REP fixture decodes");

    tgs_rep.0.enc_part =
        encrypt_tgs_rep_enc_part_with_confounder(&enc_part, &key, None, &confounder)
            .expect("TGS-REP encrypted part encrypts");

    assert_eq!(tgs_rep.0.enc_part.etype, key.etype);
    assert!(tgs_rep.0.enc_part.kvno.is_none());
    let decrypted =
        decrypt_tgs_rep_enc_part(&tgs_rep, &key).expect("TGS-REP encrypted part decrypts");
    assert_eq!(decrypted, enc_part);
}

#[test]
fn builds_and_decrypts_kdc_rep_enc_parts_with_random_confounders() {
    let enc_part = decode_enc_kdc_rep_part(&decode_hex(MARSHALLED_ENC_KDC_REP_PART))
        .expect("EncKdcRepPart decodes");
    let key = reply_key();
    let mut as_rep = decode_as_rep(&decode_hex(MARSHALLED_AS_REP)).expect("AS-REP fixture decodes");
    let mut tgs_rep =
        decode_tgs_rep(&decode_hex(MARSHALLED_TGS_REP)).expect("TGS-REP fixture decodes");

    as_rep.0.enc_part =
        encrypt_as_rep_enc_part(&enc_part, &key, None).expect("AS-REP encrypted part encrypts");
    tgs_rep.0.enc_part =
        encrypt_tgs_rep_enc_part(&enc_part, &key, None).expect("TGS-REP encrypted part encrypts");

    assert_eq!(
        decrypt_as_rep_enc_part(&as_rep, &key).expect("AS-REP encrypted part decrypts"),
        enc_part,
    );
    assert_eq!(
        decrypt_tgs_rep_enc_part(&tgs_rep, &key).expect("TGS-REP encrypted part decrypts"),
        enc_part,
    );
}

#[test]
fn rejects_kdc_rep_enc_part_key_etype_mismatch() {
    let enc_part = decode_enc_kdc_rep_part(&decode_hex(MARSHALLED_ENC_KDC_REP_PART))
        .expect("EncKdcRepPart decodes");
    let key = reply_key();
    let mut as_rep = decode_as_rep(&decode_hex(MARSHALLED_AS_REP)).expect("AS-REP fixture decodes");
    as_rep.0.enc_part =
        encrypt_as_rep_enc_part(&enc_part, &key, None).expect("AS-REP encrypted part encrypts");
    let wrong_key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error =
        decrypt_as_rep_enc_part(&as_rep, &wrong_key).expect_err("wrong etype key is rejected");

    assert!(matches!(
        error,
        Error::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        }
    ));
}

#[test]
fn exposes_kdc_rep_key_usage_constants() {
    assert_eq!(AS_REP_ENCPART_USAGE, 3);
    assert_eq!(TGS_REP_ENCPART_SESSION_KEY_USAGE, 8);
}

fn assert_kdc_rep_fields(
    rep: &rasn_kerberos::KdcRep,
    expected_msg_type: i32,
    expected_padata_count: usize,
) {
    assert_eq!(rep.pvno, Integer::from(5));
    assert_eq!(rep.msg_type, Integer::from(expected_msg_type));
    assert_eq!(
        rep.padata.as_ref().map(Vec::len).unwrap_or_default(),
        expected_padata_count,
    );
    if let Some(padata) = &rep.padata {
        for entry in padata {
            assert_eq!(entry.r#type, 13);
            assert_eq!(entry.value.as_ref(), b"pa-data");
        }
    }
    assert_eq!(rep.crealm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(rep.cname.r#type, 1);
    assert_eq!(
        principal_components(&rep.cname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    assert_eq!(rep.ticket.tkt_vno, Integer::from(5));
    assert_eq!(rep.ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(rep.ticket.sname.r#type, 1);
    assert_eq!(
        principal_components(&rep.ticket.sname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    assert_eq!(rep.ticket.enc_part.etype, 0);
    assert_eq!(rep.ticket.enc_part.kvno, Some(5));
    assert_eq!(
        rep.ticket.enc_part.cipher.as_ref(),
        b"krbASN.1 test message"
    );
    assert_eq!(rep.enc_part.etype, 0);
    assert_eq!(rep.enc_part.kvno, Some(5));
    assert_eq!(rep.enc_part.cipher.as_ref(), b"krbASN.1 test message");
}

fn assert_enc_kdc_rep_part_fields(enc_part: &rasn_kerberos::EncKdcRepPart, expected_flags: u32) {
    assert_eq!(enc_part.key.r#type, 1);
    assert_eq!(enc_part.key.value.as_ref(), b"12345678");
    assert_eq!(enc_part.last_req.len(), 2);
    for last_req in &enc_part.last_req {
        assert_eq!(last_req.r#type, -5);
        assert_eq!(last_req.value.0.timestamp(), TEST_TIME_SECONDS);
    }
    assert_eq!(enc_part.nonce, 42);
    assert_eq!(ticket_flags_to_bits(&enc_part.flags), expected_flags);
    assert_eq!(enc_part.auth_time.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(enc_part.end_time.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(enc_part.srealm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(enc_part.sname.r#type, 1);
    assert_eq!(
        principal_components(&enc_part.sname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: decode_hex(REPLY_KEY),
    }
}

fn principal_components(name: &rasn_kerberos::PrincipalName) -> Vec<&[u8]> {
    name.string
        .iter()
        .map(|component| component.as_bytes())
        .collect()
}

fn ticket_flags_to_bits(flags: &rasn_kerberos::TicketFlags) -> u32 {
    let raw = flags.0.as_raw_slice();
    u32::from_be_bytes([
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ])
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
