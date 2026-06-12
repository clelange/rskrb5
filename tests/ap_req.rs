#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::ap_req::{
    AP_REQ_AUTHENTICATOR_USAGE, Error, KRB_AP_REQ_MSG_TYPE, TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE,
    ap_options_from_bits, ap_options_to_bits, authenticator_usage_for_ticket, build_ap_req,
    build_ap_req_with_confounder, decode_ap_req, decode_authenticator,
    decrypt_ap_req_authenticator, encode_ap_req, encode_build_ap_req_with_confounder,
};
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::EncryptionKey;

const MARSHALLED_AP_REQ: &str = concat!(
    "6E819D30819AA003020105A10302010EA207030500FEDCBA98A35E615C",
    "305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018",
    "A003020101A111300F1B066866747361691B056578747261A3253023A0",
    "03020100A103020105A21704156B726241534E2E312074657374206D65",
    "7373616765A4253023A003020100A103020105A21704156B726241534E",
    "2E312074657374206D657373616765",
);
const MARSHALLED_AUTHENTICATOR: &str = concat!(
    "6281A130819EA003020105A1101B0E415448454E412E4D49542E454455",
    "A21A3018A003020101A111300F1B066866747361691B056578747261A3",
    "0F300DA003020101A106040431323334A405020301E240A511180F3139",
    "3934303631303036303331375AA6133011A003020101A10A0408313233",
    "3435363738A703020111A8243022300FA003020101A1080406666F6F62",
    "6172300FA003020101A1080406666F6F626172",
);
const TEST_TIME_SECONDS: i64 = 771_228_197;
const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

#[test]
fn decodes_gokrb5_ap_req_fixture() {
    let bytes = decode_hex(MARSHALLED_AP_REQ);

    let ap_req = decode_ap_req(&bytes).expect("AP-REQ decodes");

    assert_eq!(ap_req.pvno, Integer::from(5));
    assert_eq!(ap_req.msg_type, Integer::from(KRB_AP_REQ_MSG_TYPE));
    assert_eq!(ap_options_to_bits(&ap_req.ap_options), 0xfedc_ba98);
    assert_eq!(ap_req.ticket.tkt_vno, Integer::from(5));
    assert_eq!(
        kerberos_string_bytes(&ap_req.ticket.realm),
        b"ATHENA.MIT.EDU"
    );
    assert_eq!(ap_req.ticket.sname.r#type, 1);
    assert_eq!(
        principal_components(&ap_req.ticket.sname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    assert_eq!(ap_req.ticket.enc_part.etype, 0);
    assert_eq!(ap_req.ticket.enc_part.kvno, Some(5));
    assert_eq!(
        ap_req.ticket.enc_part.cipher.as_ref(),
        b"krbASN.1 test message",
    );
    assert_eq!(ap_req.authenticator.etype, 0);
    assert_eq!(ap_req.authenticator.kvno, Some(5));
    assert_eq!(
        ap_req.authenticator.cipher.as_ref(),
        b"krbASN.1 test message"
    );
    assert_eq!(encode_ap_req(&ap_req).expect("AP-REQ encodes"), bytes);
}

#[test]
fn decodes_gokrb5_authenticator_fixture() {
    let authenticator =
        decode_authenticator(&decode_hex(MARSHALLED_AUTHENTICATOR)).expect("Authenticator decodes");

    assert_eq!(authenticator.authenticator_vno, Integer::from(5));
    assert_eq!(
        kerberos_string_bytes(&authenticator.crealm),
        b"ATHENA.MIT.EDU"
    );
    assert_eq!(authenticator.cname.r#type, 1);
    assert_eq!(
        principal_components(&authenticator.cname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    let checksum = authenticator.cksum.as_ref().expect("checksum");
    assert_eq!(checksum.r#type, 1);
    assert_eq!(checksum.checksum.as_ref(), b"1234");
    assert_eq!(authenticator.cusec, Integer::from(123_456));
    assert_eq!(authenticator.ctime.0.timestamp(), TEST_TIME_SECONDS);
    let subkey = authenticator.subkey.as_ref().expect("subkey");
    assert_eq!(subkey.r#type, 1);
    assert_eq!(subkey.value.as_ref(), b"12345678");
    assert_eq!(authenticator.seq_number, Some(17));
    assert_eq!(
        authenticator
            .authorization_data
            .as_ref()
            .expect("authorization data")
            .len(),
        2,
    );
}

#[test]
fn builds_and_decrypts_ap_req_with_explicit_confounder() {
    let fixture = decode_ap_req(&decode_hex(MARSHALLED_AP_REQ)).expect("AP-REQ decodes");
    let authenticator =
        decode_authenticator(&decode_hex(MARSHALLED_AUTHENTICATOR)).expect("Authenticator decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x44; etype.confounder_len()];

    let ap_req = build_ap_req_with_confounder(
        fixture.ticket.clone(),
        ap_options_from_bits(0x0102_0304),
        &authenticator,
        &key,
        AP_REQ_AUTHENTICATOR_USAGE,
        Some(9),
        &confounder,
    )
    .expect("AP-REQ builds");

    assert_eq!(ap_req.pvno, Integer::from(5));
    assert_eq!(ap_req.msg_type, Integer::from(KRB_AP_REQ_MSG_TYPE));
    assert_eq!(ap_options_to_bits(&ap_req.ap_options), 0x0102_0304);
    assert_eq!(ap_req.authenticator.etype, key.etype);
    assert_eq!(ap_req.authenticator.kvno, Some(9));
    let decrypted = decrypt_ap_req_authenticator(&ap_req, &key, AP_REQ_AUTHENTICATOR_USAGE)
        .expect("Authenticator decrypts");
    assert_eq!(decrypted, authenticator);
}

#[test]
fn encodes_built_ap_req_with_explicit_confounder() {
    let fixture = decode_ap_req(&decode_hex(MARSHALLED_AP_REQ)).expect("AP-REQ decodes");
    let authenticator =
        decode_authenticator(&decode_hex(MARSHALLED_AUTHENTICATOR)).expect("Authenticator decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x22; etype.confounder_len()];

    let encoded = encode_build_ap_req_with_confounder(
        fixture.ticket,
        ap_options_from_bits(0),
        &authenticator,
        &key,
        AP_REQ_AUTHENTICATOR_USAGE,
        None,
        &confounder,
    )
    .expect("AP-REQ encodes");
    let decoded = decode_ap_req(&encoded).expect("encoded AP-REQ decodes");

    assert_eq!(decoded.authenticator.etype, key.etype);
    assert!(decoded.authenticator.kvno.is_none());
    let decrypted = decrypt_ap_req_authenticator(&decoded, &key, AP_REQ_AUTHENTICATOR_USAGE)
        .expect("Authenticator decrypts");
    assert_eq!(decrypted, authenticator);
}

#[test]
fn builds_and_decrypts_ap_req_with_random_confounder() {
    let fixture = decode_ap_req(&decode_hex(MARSHALLED_AP_REQ)).expect("AP-REQ decodes");
    let authenticator =
        decode_authenticator(&decode_hex(MARSHALLED_AUTHENTICATOR)).expect("Authenticator decodes");
    let key = reply_key();

    let ap_req = build_ap_req(
        fixture.ticket,
        ap_options_from_bits(0),
        &authenticator,
        &key,
        AP_REQ_AUTHENTICATOR_USAGE,
        None,
    )
    .expect("AP-REQ builds");

    let decrypted = decrypt_ap_req_authenticator(&ap_req, &key, AP_REQ_AUTHENTICATOR_USAGE)
        .expect("Authenticator decrypts");
    assert_eq!(decrypted, authenticator);
}

#[test]
fn selects_tgs_authenticator_usage_for_krbtgt_tickets() {
    let mut ap_req = decode_ap_req(&decode_hex(MARSHALLED_AP_REQ)).expect("AP-REQ decodes");

    assert_eq!(
        authenticator_usage_for_ticket(&ap_req.ticket),
        AP_REQ_AUTHENTICATOR_USAGE,
    );

    ap_req.ticket.sname.r#type = 2;
    ap_req.ticket.sname.string = vec![kerberos_string("krbtgt"), kerberos_string("ATHENA.MIT.EDU")];

    assert_eq!(
        authenticator_usage_for_ticket(&ap_req.ticket),
        TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE,
    );
}

#[test]
fn rejects_ap_req_authenticator_key_etype_mismatch() {
    let fixture = decode_ap_req(&decode_hex(MARSHALLED_AP_REQ)).expect("AP-REQ decodes");
    let authenticator =
        decode_authenticator(&decode_hex(MARSHALLED_AUTHENTICATOR)).expect("Authenticator decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x44; etype.confounder_len()];
    let ap_req = build_ap_req_with_confounder(
        fixture.ticket,
        ap_options_from_bits(0),
        &authenticator,
        &key,
        AP_REQ_AUTHENTICATOR_USAGE,
        None,
        &confounder,
    )
    .expect("AP-REQ builds");
    let wrong_key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error = decrypt_ap_req_authenticator(&ap_req, &wrong_key, AP_REQ_AUTHENTICATOR_USAGE)
        .expect_err("wrong etype key is rejected");

    assert!(matches!(
        error,
        Error::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        }
    ));
}

#[test]
fn exposes_ap_req_key_usage_constants() {
    assert_eq!(AP_REQ_AUTHENTICATOR_USAGE, 11);
    assert_eq!(TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE, 7);
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: decode_hex(REPLY_KEY),
    }
}

fn kerberos_string(input: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::from_bytes(input.as_bytes()).expect("KerberosString encodes")
}

fn kerberos_string_bytes(input: &rasn_kerberos::KerberosString) -> &[u8] {
    input.as_bytes()
}

fn principal_components(name: &rasn_kerberos::PrincipalName) -> Vec<&[u8]> {
    name.string
        .iter()
        .map(|component| component.as_bytes())
        .collect()
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
