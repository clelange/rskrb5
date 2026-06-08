#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::kadmin::{
    ChangePasswdData, ChangePasswordResult, Error as KadminError, Reply, Request,
};
use rskrb5::keytab::EncryptionKey;

const MARSHALLED_CHANGE_PASSWD_DATA: &str = "3036a00d040b6e657770617373776f7264a1163014a003020101a10d300b1b09746573747573657231a20d1b0b544553542e474f4b524235";
const MARSHALLED_KPASSWD_REQ: &str = "037aff8002c16e8202bd308202b9a003020105a10302010ea20703050000000000a38201f1618201ed308201e9a003020105a10d1b0b544553542e474f4b524235a21d301ba003020101a11430121b066b61646d696e1b086368616e67657077a38201b2308201aea003020111a103020101a28201a00482019ca3de94df50e8e9fe7a8c9386f594f469bf08874407fc7b95ddcf22110ef63e62ff0ba3c31c3bb725dc1dde1f4c2f69a4973b4b43c9b4b31f71f676d5e8e7b4d7906b1dfacc9897d865b17f934fb96b802344463bb0746fdd39e9e48ff1b2665dc895a74d3d3aac89512b43bd8ead8f455b9b819cc6f6a34fb7c5975d7c2dbd4349524961215b98f33f5747f1e0c89f3b3637462308953940741ab7fc38ae817ba85800dd911bb78b42264f2d285c2a0a33ca21c1a3d281ec14614010db31c3e3f4d4622b799f97b3d31c4445411278fec62dd8e6e349db280aaa4419b53ef6fbc01f0206bcfea2cbe835b46764c03c138722e54dab53a1080e5d6c99f8cd7a948880677176cfc2d3800f9ef64d1ec4f8bdadc1ae409990c4855a82e265682e8ddaa6dea70a1d7855f3e1e766f5efe428dd6da71c585f5d17d8f81e8f2a4f4b2245f5ff2cc444a2a1ae5d16a15d588597219d5659da537f752ca9b572b635088b325b60e8e62fd99487872261f41dcc466516b89992d277bb8b3a1ca770671fca36dd33c3dd6dab643e6710280661029254054273151ccfca9aaddc55a481ae3081aba003020112a103020101a2819e04819be66387f971d751d7d3ebb6acd815a0991e0ed9f07e2643783e7961fb88127b31f767bf00d1d071a81858b101f4d45460412d8013228f942bc51891e95a06aefa8cedd95e5a3e6e65597c0f05c19ee54dc6dc00b1a3f9d7a95516b5e447c40cd5b462ed6b17a007670311efa44dbe939cab11072b9af1443c3203767bb1a3240542db06dffcaebcedd5c335bb295127bc0e6d99f2c1e87f68de1f547581b03081ada003020105a103020115a381a030819da003020112a103020101a2819004818df272b2726c8f31c578f3b4275bc283828716010a20f0c4369bff474fcf202537060a71edcbe8ba720d0d9b2bac26b58353dc5b2945570374928a819eb3526362eda328e704f1a5ebe3272eed0fa6a6aa7d0f32c4fc0bd2e4ea52a8834ea7b5fb018934df87c18ab625f5c07f6c28e202e0cec63bcc37b1d381d64937998c1bdcd1585695eeffb75f8ce9e736b3";
const MARSHALLED_KPASSWD_REP: &str = "00ec0001008c6f8189308186a003020105a10302010fa27a3078a003020112a271046f57cb442fd321312aff0b2dcda70fe436812f9805611adf3403ab6cd7708604e86e77f765a8486864f0dbf8d5d065a63790370bc110ed1e3c7eae9890e02407e8a8b349703fed1e7f165e1261a822c5b3e6823c282884f59afeb9f84f2a9845994135dd307eb2f544874393c1c455d475583056a003020105a103020115a34a3048a003020112a241043fdd3edaf0b6cbcab5b663189bafc0a19e6cc03b3c59d989c403735748ebc36088bad852add0f62581eed515fc1f297324df4fa12cb94b7ad5db257165369db5";
const KRB_ERROR_WITH_EDATA: &str = "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461";

#[test]
fn change_passwd_data_matches_gokrb5_fixture() {
    let value = ChangePasswdData {
        new_passwd: b"newpassword".to_vec().into(),
        targ_name: Some(principal_name(1, &["testuser1"])),
        targ_realm: Some(kerberos_string("TEST.GOKRB5")),
    };
    let expected = decode_hex(MARSHALLED_CHANGE_PASSWD_DATA);

    let encoded = rasn::der::encode(&value).expect("ChangePasswdData encodes");
    assert_eq!(encoded, expected);

    let decoded: ChangePasswdData = rasn::der::decode(&expected).expect("ChangePasswdData decodes");
    assert_eq!(decoded, value);
    assert_eq!(
        rasn::der::encode(&decoded).expect("ChangePasswdData re-encodes"),
        expected
    );
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

fn principal_name(name_type: i32, components: &[&str]) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: name_type,
        string: components
            .iter()
            .map(|component| kerberos_string(component))
            .collect(),
    }
}

fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::try_from(value).expect("valid KerberosString")
}

fn decode_hex(input: &str) -> Vec<u8> {
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
