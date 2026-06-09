#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rskrb5::messages::{EncryptedData, Error, KrbErrorInfo, decode_der, encode_der};

const ENCRYPTED_DATA: &str =
    "3023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const ENCRYPTED_DATA_MSB_SET_KVNO: &str =
    "3026A003020100A1060204FF000000A21704156B726241534E2E312074657374206D657373616765";
const ENCRYPTED_DATA_KVNO_NEGATIVE_ONE: &str =
    "3023A003020100A1030201FFA21704156B726241534E2E312074657374206D657373616765";
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
const TEST_CIPHER: &[u8] = b"krbASN.1 test message";
const TEST_TIME_SECONDS: u64 = 771_228_197;

#[test]
fn encrypted_data_roundtrips_gokrb5_fixtures_exactly() {
    for (fixture, expected_kvno) in [
        (ENCRYPTED_DATA, 5),
        (ENCRYPTED_DATA_MSB_SET_KVNO, -16_777_216),
        (ENCRYPTED_DATA_KVNO_NEGATIVE_ONE, -1),
    ] {
        let bytes = decode_hex(fixture);
        let decoded: EncryptedData = rasn::der::decode(&bytes).expect("EncryptedData decodes");

        assert_eq!(decoded.etype, 0);
        assert_eq!(
            decoded.kvno_i32().expect("kvno fits i32"),
            Some(expected_kvno)
        );
        assert_eq!(decoded.cipher.as_ref(), TEST_CIPHER);
        assert_eq!(
            rasn::der::encode(&decoded).expect("EncryptedData encodes"),
            bytes
        );
    }
}

#[test]
fn encrypted_data_converts_to_rasn_for_normal_kvno() {
    let decoded = decode_encrypted_data(ENCRYPTED_DATA);
    let rasn = decoded.try_to_rasn().expect("normal kvno fits u32");

    assert_eq!(rasn.etype, 0);
    assert_eq!(rasn.kvno, Some(5));
    assert_eq!(rasn.cipher.as_ref(), TEST_CIPHER);
    assert_eq!(EncryptedData::from_rasn(rasn), decoded);
}

#[test]
fn encrypted_data_rejects_signed_kvno_for_rasn_conversion() {
    for fixture in [
        ENCRYPTED_DATA_MSB_SET_KVNO,
        ENCRYPTED_DATA_KVNO_NEGATIVE_ONE,
    ] {
        let decoded = decode_encrypted_data(fixture);
        let error = decoded
            .try_to_rasn()
            .expect_err("negative kvno cannot convert to u32");

        assert!(matches!(error, Error::KvnoOutOfRange { target: "u32", .. }));
    }
}

#[test]
fn krb_error_decodes_and_roundtrips_gokrb5_fixture() {
    let bytes = decode_hex(KRB_ERROR);
    let decoded: rasn_kerberos::KrbError =
        decode_der("KRB-ERROR", &bytes).expect("KRB-ERROR decodes");
    let info = KrbErrorInfo::from_rasn(&decoded).expect("KRB-ERROR info builds");

    assert_eq!(info.ctime, Some(timestamp(TEST_TIME_SECONDS)));
    assert_eq!(info.cusec, Some(123_456));
    assert_eq!(info.stime, timestamp(TEST_TIME_SECONDS));
    assert_eq!(info.susec, 123_456);
    assert_eq!(info.error_code, 60);
    let client = info.client.expect("client principal exists");
    assert_eq!(client.realm, "ATHENA.MIT.EDU");
    assert_eq!(client.name_type, 1);
    assert_eq!(client.components, ["hftsai", "extra"]);
    assert_eq!(client.name(), "hftsai/extra");
    assert_eq!(info.service.realm, "ATHENA.MIT.EDU");
    assert_eq!(info.service.name_type, 1);
    assert_eq!(info.service.components, ["hftsai", "extra"]);
    assert_eq!(info.e_text.as_deref(), Some("krb5data"));
    assert_eq!(info.e_data.as_deref(), Some(b"krb5data".as_slice()));
    assert_eq!(
        encode_der("KRB-ERROR", &decoded).expect("KRB-ERROR encodes"),
        bytes
    );
}

#[test]
fn krb_error_optional_nulls_decode_and_roundtrip() {
    let bytes = decode_hex(KRB_ERROR_OPTIONALS_NULL);
    let decoded: rasn_kerberos::KrbError =
        decode_der("KRB-ERROR", &bytes).expect("KRB-ERROR decodes");
    let info = KrbErrorInfo::decode_der(&bytes).expect("KRB-ERROR info decodes");

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
        encode_der("KRB-ERROR", &decoded).expect("KRB-ERROR encodes"),
        bytes
    );
}

fn decode_encrypted_data(fixture: &str) -> EncryptedData {
    rasn::der::decode(&decode_hex(fixture)).expect("EncryptedData fixture decodes")
}

fn timestamp(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn decode_hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture hex decodes")
}
