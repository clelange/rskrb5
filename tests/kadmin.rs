#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rskrb5::kadmin::ChangePasswdData;

const MARSHALLED_CHANGE_PASSWD_DATA: &str = "3036a00d040b6e657770617373776f7264a1163014a003020101a10d300b1b09746573747573657231a20d1b0b544553542e474f4b524235";

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

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit: {value}"),
    }
}
