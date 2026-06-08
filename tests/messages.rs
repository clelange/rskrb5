#![cfg(feature = "messages")]

use rskrb5::messages::{EncryptedData, Error};

const ENCRYPTED_DATA: &str =
    "3023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
const ENCRYPTED_DATA_MSB_SET_KVNO: &str =
    "3026A003020100A1060204FF000000A21704156B726241534E2E312074657374206D657373616765";
const ENCRYPTED_DATA_KVNO_NEGATIVE_ONE: &str =
    "3023A003020100A1030201FFA21704156B726241534E2E312074657374206D657373616765";
const TEST_CIPHER: &[u8] = b"krbASN.1 test message";

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

fn decode_encrypted_data(fixture: &str) -> EncryptedData {
    rasn::der::decode(&decode_hex(fixture)).expect("EncryptedData fixture decodes")
}

fn decode_hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture hex decodes")
}
