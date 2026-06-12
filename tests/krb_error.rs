#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::krb_error::{
    Error, KRB_ERROR_MSG_TYPE, KRB5_PVNO, decode_krb_error, decode_krb_error_info,
    decode_method_data, encode_krb_error, encode_method_data, preauth_method_data,
    validate_krb_error,
};

const KRB_ERROR: &str = concat!(
    "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305",
    "020301E240A411180F31393934303631303036303331375AA505020301E240A60302013C",
    "A7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866",
    "747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003",
    "020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A",
    "04086B72623564617461",
);
const KRB_ERROR_OPTIONALS_NULL: &str = concat!(
    "7E60305EA003020105A10302011EA305020301E240A411180F3139393430363130303630",
    "3331375AA505020301E240A60302013CA9101B0E415448454E412E4D49542E454455AA1A",
    "3018A003020101A111300F1B066866747361691B056578747261",
);
const TEST_TIME_SECONDS: u64 = 771_228_197;
const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
const PA_ETYPE_INFO2: i32 = 19;

#[test]
fn decodes_and_roundtrips_gokrb5_krb_error_fixture() {
    let bytes = decode_hex(KRB_ERROR);

    let krb_error = decode_krb_error(&bytes).expect("KRB-ERROR decodes");
    let info = decode_krb_error_info(&bytes).expect("KRB-ERROR info decodes");

    assert_eq!(krb_error.pvno, Integer::from(KRB5_PVNO));
    assert_eq!(krb_error.msg_type, Integer::from(KRB_ERROR_MSG_TYPE));
    assert_eq!(info.ctime, Some(timestamp(TEST_TIME_SECONDS)));
    assert_eq!(info.cusec, Some(123_456));
    assert_eq!(info.stime, timestamp(TEST_TIME_SECONDS));
    assert_eq!(info.susec, 123_456);
    assert_eq!(info.error_code, 60);
    assert_eq!(
        info.client.as_ref().expect("client principal exists").realm,
        "ATHENA.MIT.EDU"
    );
    assert_eq!(
        info.client
            .as_ref()
            .expect("client principal exists")
            .name(),
        "hftsai/extra"
    );
    assert_eq!(info.service.realm, "ATHENA.MIT.EDU");
    assert_eq!(info.service.name(), "hftsai/extra");
    assert_eq!(info.e_text.as_deref(), Some("krb5data"));
    assert_eq!(info.e_data.as_deref(), Some(b"krb5data".as_slice()));
    assert_eq!(
        encode_krb_error(&krb_error).expect("KRB-ERROR encodes"),
        bytes
    );
}

#[test]
fn decodes_and_roundtrips_gokrb5_krb_error_optionals_null_fixture() {
    let bytes = decode_hex(KRB_ERROR_OPTIONALS_NULL);

    let krb_error = decode_krb_error(&bytes).expect("KRB-ERROR decodes");
    let info = decode_krb_error_info(&bytes).expect("KRB-ERROR info decodes");

    assert_eq!(info.ctime, None);
    assert_eq!(info.cusec, Some(123_456));
    assert_eq!(info.stime, timestamp(TEST_TIME_SECONDS));
    assert_eq!(info.susec, 123_456);
    assert_eq!(info.error_code, 60);
    assert_eq!(info.client, None);
    assert_eq!(info.service.realm, "ATHENA.MIT.EDU");
    assert_eq!(info.service.name(), "hftsai/extra");
    assert_eq!(info.e_text, None);
    assert_eq!(info.e_data, None);
    assert_eq!(
        encode_krb_error(&krb_error).expect("KRB-ERROR encodes"),
        bytes
    );
}

#[test]
fn rejects_non_krb_error_message_type() {
    let mut krb_error = decode_krb_error(&decode_hex(KRB_ERROR)).expect("KRB-ERROR decodes");
    krb_error.msg_type = Integer::from(11);

    let error = validate_krb_error(&krb_error).expect_err("wrong msg-type is rejected");

    assert_eq!(
        error,
        Error::InvalidMessage {
            field: "msg-type",
            expected: KRB_ERROR_MSG_TYPE,
            actual: "11".to_owned(),
        }
    );
}

#[test]
fn decodes_method_data_from_preauth_required_error() {
    let mut krb_error = decode_krb_error(&decode_hex(KRB_ERROR)).expect("KRB-ERROR decodes");
    let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
        r#type: PA_ETYPE_INFO2,
        value: vec![1, 2, 3].into(),
    }]);
    krb_error.error_code = KDC_ERR_PREAUTH_REQUIRED;
    krb_error.e_data = Some(
        encode_method_data(&method_data)
            .expect("METHOD-DATA encodes")
            .into(),
    );

    let decoded =
        preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED).expect("METHOD-DATA decodes");

    assert_eq!(decoded, method_data);
    assert_eq!(
        decode_method_data(krb_error.e_data.as_ref().expect("e-data exists").as_ref())
            .expect("METHOD-DATA decodes"),
        method_data
    );
}

#[test]
fn ignores_method_data_when_error_code_does_not_match() {
    let krb_error = decode_krb_error(&decode_hex(KRB_ERROR)).expect("KRB-ERROR decodes");

    let method_data =
        preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED).expect("helper succeeds");

    assert!(method_data.is_empty());
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex decodes")
}

fn timestamp(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}
