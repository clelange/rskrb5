#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::EncryptionKey;
use rskrb5::krb_priv::{
    EncKrbPrivPartOptions, KRB_PRIV_MSG_TYPE, KRB_PRIV_PVNO, build_krb_priv,
    build_krb_priv_with_confounder, decode_enc_krb_priv_part, decode_krb_priv,
    decrypt_krb_priv_enc_part, encode_enc_krb_priv_part, encode_krb_priv, ipv4_host_address,
    ipv6_host_address,
};

const MARSHALLED_KRB_PRIV: &str = concat!(
    "75333031A003020105A103020115A3253023A003020100A103020105A217",
    "04156B726241534E2E312074657374206D657373616765",
);
const MARSHALLED_ENC_KRB_PRIV_PART: &str = concat!(
    "7C4F304DA00A04086B72623564617461A111180F31393934303631303036",
    "303331375AA205020301E240A303020111A40F300DA003020102A10604",
    "0412D00023A50F300DA003020102A106040412D00023",
);
const MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL: &str = concat!(
    "7C1F301DA00A04086B72623564617461A40F300DA003020102A10604",
    "0412D00023",
);
const TEST_TIME_SECONDS: i64 = 771_228_197;

#[test]
fn decodes_and_roundtrips_gokrb5_krb_priv_fixture() {
    let bytes = decode_hex(MARSHALLED_KRB_PRIV);

    let krb_priv = decode_krb_priv(&bytes).expect("KRB-PRIV decodes");

    assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
    assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
    assert_eq!(krb_priv.enc_part.etype, 0);
    assert_eq!(krb_priv.enc_part.kvno, Some(5));
    assert_eq!(krb_priv.enc_part.cipher.as_ref(), b"krbASN.1 test message");
    assert_eq!(encode_krb_priv(&krb_priv).expect("KRB-PRIV encodes"), bytes);
}

#[test]
fn decodes_and_roundtrips_gokrb5_enc_krb_priv_part_fixture() {
    let bytes = decode_hex(MARSHALLED_ENC_KRB_PRIV_PART);

    let enc_part = decode_enc_krb_priv_part(&bytes).expect("EncKrbPrivPart decodes");

    assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
    assert_eq!(
        enc_part
            .timestamp
            .as_ref()
            .expect("timestamp")
            .0
            .timestamp(),
        TEST_TIME_SECONDS
    );
    assert_eq!(enc_part.usec, Some(Integer::from(123_456)));
    assert_eq!(enc_part.seq_number, Some(17));
    assert_eq!(
        enc_part.sender_address.addr_type,
        rasn_kerberos::HostAddress::IPV4
    );
    assert_eq!(
        enc_part.sender_address.address.as_ref(),
        decode_hex("12d00023")
    );
    assert_eq!(
        enc_part
            .recipient_address
            .as_ref()
            .expect("recipient address")
            .address
            .as_ref(),
        decode_hex("12d00023")
    );
    assert_eq!(
        encode_enc_krb_priv_part(&enc_part).expect("EncKrbPrivPart encodes"),
        bytes
    );
}

#[test]
fn decodes_and_roundtrips_gokrb5_enc_krb_priv_part_optionals_null_fixture() {
    let bytes = decode_hex(MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL);

    let enc_part = decode_enc_krb_priv_part(&bytes).expect("EncKrbPrivPart decodes");

    assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
    assert!(enc_part.timestamp.is_none());
    assert!(enc_part.usec.is_none());
    assert!(enc_part.seq_number.is_none());
    assert_eq!(
        enc_part.sender_address.addr_type,
        rasn_kerberos::HostAddress::IPV4
    );
    assert_eq!(
        enc_part.sender_address.address.as_ref(),
        decode_hex("12d00023")
    );
    assert!(enc_part.recipient_address.is_none());
    assert_eq!(
        encode_enc_krb_priv_part(&enc_part).expect("EncKrbPrivPart encodes"),
        bytes
    );
}

#[test]
fn builds_and_decrypts_krb_priv_with_explicit_confounder() {
    let key = EncryptionKey {
        etype: 18,
        value: vec![0x11; 32],
    };
    let sender_address = ipv4_host_address([127, 0, 0, 1]);
    let recipient_address = ipv6_host_address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let options = EncKrbPrivPartOptions::new(sender_address.clone())
        .with_sequence_number(7)
        .with_recipient_address(recipient_address.clone());
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x22; etype.confounder_len()];

    let krb_priv = build_krb_priv_with_confounder(b"krb5data", options, &key, Some(3), &confounder)
        .expect("KRB-PRIV builds");

    assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
    assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
    assert_eq!(krb_priv.enc_part.etype, key.etype);
    assert_eq!(krb_priv.enc_part.kvno, Some(3));

    let enc_part =
        decrypt_krb_priv_enc_part(&krb_priv, &key).expect("KRB-PRIV decrypts and decodes");

    assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
    assert_eq!(enc_part.sender_address, sender_address);
    assert_eq!(enc_part.recipient_address, Some(recipient_address));
    assert_eq!(enc_part.seq_number, Some(7));
}

#[test]
fn builds_and_decrypts_krb_priv_with_random_confounder() {
    let key = EncryptionKey {
        etype: 18,
        value: vec![0x11; 32],
    };
    let options = EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]));

    let krb_priv = build_krb_priv(b"krb5data", options, &key, None).expect("KRB-PRIV builds");
    let enc_part =
        decrypt_krb_priv_enc_part(&krb_priv, &key).expect("KRB-PRIV decrypts and decodes");

    assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex decodes")
}
