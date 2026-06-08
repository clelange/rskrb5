#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::kadmin::{
    ChangePasswdData, ChangePasswordResult, Error as KadminError, KPASSWD_AUTHERROR,
    KPASSWD_SUCCESS, Reply, Request,
};
use rskrb5::keytab::EncryptionKey;

const MARSHALLED_CHANGE_PASSWD_DATA: &str = "3036a00d040b6e657770617373776f7264a1163014a003020101a10d300b1b09746573747573657231a20d1b0b544553542e474f4b524235";
const MARSHALLED_KPASSWD_REQ: &str = include_str!("fixtures/kpasswd-request.hex");
const MARSHALLED_KPASSWD_REP: &str = "00ec0001008c6f8189308186a003020105a10302010fa27a3078a003020112a271046f57cb442fd321312aff0b2dcda70fe436812f9805611adf3403ab6cd7708604e86e77f765a8486864f0dbf8d5d065a63790370bc110ed1e3c7eae9890e02407e8a8b349703fed1e7f165e1261a822c5b3e6823c282884f59afeb9f84f2a9845994135dd307eb2f544874393c1c455d475583056a003020105a103020115a34a3048a003020112a241043fdd3edaf0b6cbcab5b663189bafc0a19e6cc03b3c59d989c403735748ebc36088bad852add0f62581eed515fc1f297324df4fa12cb94b7ad5db257165369db5";
const KRB_ERROR_WITH_EDATA: &str = "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461";

#[test]
fn change_passwd_data_matches_gokrb5_fixture() {
    let value = ChangePasswdData::for_target(b"newpassword", 1, ["testuser1"], "TEST.GOKRB5")
        .expect("targeted ChangePasswdData builds");
    let expected = decode_hex(MARSHALLED_CHANGE_PASSWD_DATA);

    let encoded = value.encode_der().expect("ChangePasswdData encodes");
    assert_eq!(encoded, expected);

    let decoded = ChangePasswdData::decode_der(&expected).expect("ChangePasswdData decodes");
    assert_eq!(decoded, value);
    assert_eq!(
        decoded.encode_der().expect("ChangePasswdData re-encodes"),
        expected
    );
}

#[test]
fn change_passwd_data_builds_password_only_payload() {
    let value = ChangePasswdData::new(b"newpassword");
    let encoded = value.encode_der().expect("ChangePasswdData encodes");
    let decoded = ChangePasswdData::decode_der(&encoded).expect("ChangePasswdData decodes");

    assert_eq!(decoded, value);
    assert_eq!(decoded.new_passwd.as_ref(), b"newpassword");
    assert!(decoded.targ_name.is_none());
    assert!(decoded.targ_realm.is_none());
}

#[test]
fn kpasswd_request_roundtrips_gokrb5_fixture() {
    let bytes = decode_hex(MARSHALLED_KPASSWD_REQ);
    let request = Request::parse(&bytes).expect("kpasswd request parses");

    assert_eq!(read_u16(&bytes, 0) as usize, bytes.len());
    assert_eq!(read_u16(&bytes, 2), 0xff80);
    assert_eq!(read_u16(&bytes, 4), 705);
    assert_eq!(request.ap_req.pvno, Integer::from(5));
    assert_eq!(request.ap_req.msg_type, Integer::from(14));
    assert_eq!(request.ap_req.authenticator.etype, 18);
    assert_eq!(request.krb_priv.pvno, Integer::from(5));
    assert_eq!(request.krb_priv.msg_type, Integer::from(21));
    assert_eq!(request.krb_priv.enc_part.etype, 18);
    assert_eq!(request.encode().expect("request encodes"), bytes);
}

#[test]
fn kpasswd_request_rejects_malformed_frames() {
    assert!(matches!(
        Request::parse(&[0, 6, 0, 1, 0, 0]),
        Err(KadminError::InvalidRequestVersion(1))
    ));

    assert!(matches!(
        Request::parse(&[0, 7, 0xff, 0x80, 0, 0, 0]),
        Err(KadminError::InvalidApReqLength {
            ap_req_length: 0,
            body_length: 1
        })
    ));

    assert!(matches!(
        Request::parse(&[0, 7, 0xff, 0x80, 0, 1, 0]),
        Err(KadminError::InvalidApReqLength {
            ap_req_length: 1,
            body_length: 1
        })
    ));
}

#[test]
fn kpasswd_reply_matches_gokrb5_fixture() {
    let bytes = decode_hex(MARSHALLED_KPASSWD_REP);
    let reply = Reply::parse(&bytes).expect("kpasswd reply parses");

    assert_eq!(reply.message_length, 236);
    assert_eq!(reply.version, 1);
    assert_eq!(reply.ap_rep_length, 140);
    assert!(!reply.is_krb_error());
    assert!(reply.krb_error.is_none());
    assert!(reply.result.is_none());

    let ap_rep = reply.ap_rep.expect("AP-REP parsed");
    assert_eq!(ap_rep.pvno, Integer::from(5));
    assert_eq!(ap_rep.msg_type, Integer::from(15));
    assert_eq!(ap_rep.enc_part.etype, 18);

    let krb_priv = reply.krb_priv.expect("KRB-PRIV parsed");
    assert_eq!(krb_priv.pvno, Integer::from(5));
    assert_eq!(krb_priv.msg_type, Integer::from(21));
    assert_eq!(krb_priv.enc_part.etype, 18);
}

#[test]
fn kpasswd_reply_parses_krb_error_response_data() {
    let error = decode_hex(KRB_ERROR_WITH_EDATA);
    let frame = kpasswd_reply_frame(0, &error);
    let reply = Reply::parse(&frame).expect("KRB-ERROR reply parses");

    assert_eq!(reply.message_length as usize, frame.len());
    assert_eq!(reply.version, 1);
    assert_eq!(reply.ap_rep_length, 0);
    assert!(reply.is_krb_error());
    assert!(reply.ap_rep.is_none());
    assert!(reply.krb_priv.is_none());
    assert!(reply.krb_error.is_some());
    assert_eq!(
        reply.result,
        Some(ChangePasswordResult {
            code: u16::from_be_bytes([b'k', b'r']),
            text: "b5data".to_owned(),
        })
    );
}

#[test]
fn kpasswd_reply_decrypt_result_returns_krb_error_result() {
    let reply = Reply::parse(&kpasswd_reply_frame(0, &decode_hex(KRB_ERROR_WITH_EDATA)))
        .expect("KRB-ERROR reply parses");
    let key = EncryptionKey {
        etype: 18,
        value: vec![0; 32],
    };

    assert_eq!(
        reply
            .decrypt_result(&key)
            .expect("KRB-ERROR result needs no decrypt"),
        ChangePasswordResult {
            code: u16::from_be_bytes([b'k', b'r']),
            text: "b5data".to_owned(),
        }
    );
}

#[test]
fn kpasswd_result_success_helper_accepts_zero_code() {
    let result = ChangePasswordResult::parse(&[0, 0]).expect("success result parses");

    assert_eq!(result.code, KPASSWD_SUCCESS);
    assert!(result.is_success());
    assert_eq!(result.ensure_success(), Ok(()));
}

#[test]
fn kpasswd_result_success_helper_reports_failure_code() {
    let result = ChangePasswordResult {
        code: KPASSWD_AUTHERROR,
        text: "authentication failed".to_owned(),
    };

    assert!(!result.is_success());
    assert!(matches!(
        result.ensure_success(),
        Err(KadminError::PasswordChangeFailed { code, text })
            if code == KPASSWD_AUTHERROR && text == "authentication failed"
    ));
}

#[test]
fn kpasswd_reply_decrypt_result_rejects_wrong_key_etype() {
    let reply = Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)).expect("kpasswd reply parses");
    let key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    assert!(matches!(
        reply.decrypt_result(&key),
        Err(KadminError::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        })
    ));
}

#[test]
fn kpasswd_reply_rejects_malformed_frames() {
    assert!(matches!(
        Reply::parse(&[0, 1]),
        Err(KadminError::FrameTooShort { actual: 2 })
    ));

    assert!(matches!(
        Reply::parse(&[0, 7, 0, 1, 0, 0]),
        Err(KadminError::TruncatedFrame {
            expected: 7,
            actual: 6
        })
    ));

    assert!(matches!(
        Reply::parse(&[0, 6, 0, 2, 0, 0]),
        Err(KadminError::InvalidReplyVersion(2))
    ));

    assert!(matches!(
        Reply::parse(&[0, 7, 0, 1, 0, 1, 0]),
        Err(KadminError::InvalidApRepLength {
            ap_rep_length: 1,
            body_length: 1
        })
    ));
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0]);
            let lo = hex_nibble(pair[1]);
            (hi << 4) | lo
        })
        .collect()
}

fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Vec<u8> {
    let message_length = HEADER_LEN + body.len();
    assert!(u16::try_from(message_length).is_ok());

    let mut frame = Vec::with_capacity(message_length);
    frame.extend_from_slice(&(message_length as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&ap_rep_length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

const HEADER_LEN: usize = 6;

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit: {value}"),
    }
}
