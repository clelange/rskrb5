#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::EncryptionKey;
use rskrb5::krb_cred::{
    Error, KRB_CRED_ENCPART_USAGE, KRB_CRED_MSG_TYPE,
    decode_decrypt_krb_cred_to_ccache_credentials, decode_enc_krb_cred_part, decode_krb_cred,
    decrypt_krb_cred_enc_part, decrypt_krb_cred_to_ccache_credentials,
    decrypted_krb_cred_to_ccache_credentials,
};

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TEST_TIME_SECONDS: u32 = 771_228_197;
const KRB_CRED: &str = concat!(
    "7681F63081F3A003020105A103020116A281BF3081BC615C305AA003020105A110",
    "1B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866",
    "747361691B056578747261A3253023A003020100A103020105A21704156B726241",
    "534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448",
    "454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B",
    "056578747261A3253023A003020100A103020105A21704156B726241534E2E3120",
    "74657374206D657373616765A3253023A003020100A103020105A21704156B7262",
    "41534E2E312074657374206D657373616765",
);
const ENC_KRB_CRED_PART: &str = concat!(
    "7D8202233082021FA08201DA308201D63081E8A0133011A003020101A10A040831",
    "32333435363738A1101B0E415448454E412E4D49542E454455A21A3018A0030201",
    "01A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F",
    "31393934303631303036303331375AA511180F3139393430363130303630333137",
    "5AA611180F31393934303631303036303331375AA711180F313939343036313030",
    "36303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101",
    "A111300F1B066866747361691B056578747261AA20301E300DA003020102A10604",
    "0412D00023300DA003020102A106040412D000233081E8A0133011A003020101A1",
    "0A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018",
    "A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98",
    "A411180F31393934303631303036303331375AA511180F31393934303631303036",
    "303331375AA611180F31393934303631303036303331375AA711180F3139393430",
    "3631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A0",
    "03020101A111300F1B066866747361691B056578747261AA20301E300DA0030201",
    "02A106040412D00023300DA003020102A106040412D00023A10302012AA211180F",
    "31393934303631303036303331375AA305020301E240A40F300DA003020102A106",
    "040412D00023A50F300DA003020102A106040412D00023",
);

#[test]
fn decodes_gokrb5_krb_cred_fixture() {
    let krb_cred = decode_krb_cred(&decode_hex(KRB_CRED)).expect("KRB-CRED decodes");

    assert_eq!(krb_cred.pvno, Integer::from(5));
    assert_eq!(krb_cred.msg_type, Integer::from(KRB_CRED_MSG_TYPE));
    assert_eq!(krb_cred.tickets.len(), 2);
    assert_eq!(krb_cred.tickets[0].tkt_vno, Integer::from(5));
    assert_eq!(krb_cred.tickets[0].enc_part.etype, 0);
    assert_eq!(krb_cred.tickets[0].enc_part.kvno, Some(5));
    assert_eq!(krb_cred.enc_part.etype, 0);
    assert_eq!(krb_cred.enc_part.kvno, Some(5));
    assert_eq!(krb_cred.enc_part.cipher.as_ref(), b"krbASN.1 test message");
}

#[test]
fn decodes_gokrb5_enc_krb_cred_part_fixture() {
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");

    assert_eq!(enc_part.ticket_info.len(), 2);
    assert_eq!(enc_part.ticket_info[0].key.r#type, 1);
    assert_eq!(enc_part.ticket_info[0].key.value.as_ref(), b"12345678");
    assert_eq!(enc_part.nonce, Some(42));
    assert_eq!(enc_part.usec, Some(Integer::from(123_456)));
    assert_eq!(
        enc_part.sender_address.as_ref().expect("sender").addr_type,
        2
    );
    assert_eq!(
        enc_part
            .recipient_address
            .as_ref()
            .expect("recipient")
            .addr_type,
        2
    );
}

#[test]
fn decrypts_krb_cred_encrypted_part() {
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");
    let krb_cred = encrypted_krb_cred(&enc_part);
    let key = reply_key();

    let decrypted =
        decrypt_krb_cred_enc_part(&krb_cred, &key).expect("KRB-CRED encrypted part decrypts");

    assert_eq!(decrypted, enc_part);
}

#[test]
fn converts_decrypted_krb_cred_to_ccache_credentials() {
    let krb_cred = decode_krb_cred(&decode_hex(KRB_CRED)).expect("KRB-CRED decodes");
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");

    let credentials = decrypted_krb_cred_to_ccache_credentials(&krb_cred, &enc_part)
        .expect("KRB-CRED converts to ccache credentials");

    assert_eq!(credentials.len(), 2);
    let credential = &credentials[0];
    assert_eq!(credential.client.realm, "ATHENA.MIT.EDU");
    assert_eq!(credential.client.components, ["hftsai", "extra"]);
    assert_eq!(credential.server.realm, "ATHENA.MIT.EDU");
    assert_eq!(credential.server.components, ["hftsai", "extra"]);
    assert_eq!(credential.key.etype, 1);
    assert_eq!(credential.key.value, b"12345678");
    assert_eq!(credential.times.auth_time, TEST_TIME_SECONDS);
    assert_eq!(credential.times.start_time, TEST_TIME_SECONDS);
    assert_eq!(credential.times.end_time, TEST_TIME_SECONDS);
    assert_eq!(credential.times.renew_till, TEST_TIME_SECONDS);
    assert_eq!(credential.ticket_flags, [0xfe, 0xdc, 0xba, 0x98]);
    assert_eq!(credential.addresses.len(), 2);
    assert_eq!(credential.addresses[0].addr_type, 2);
    assert_eq!(credential.addresses[0].address, decode_hex("12d00023"));
    assert_eq!(
        credential.ticket,
        rasn::der::encode(&krb_cred.tickets[0]).expect("ticket encodes")
    );
    assert!(credential.auth_data.is_empty());
    assert!(credential.second_ticket.is_empty());
}

#[test]
fn decrypts_krb_cred_to_ccache_credentials() {
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");
    let krb_cred = encrypted_krb_cred(&enc_part);
    let key = reply_key();

    let credentials = decrypt_krb_cred_to_ccache_credentials(&krb_cred, &key)
        .expect("KRB-CRED decrypts and converts");

    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].client.components, ["hftsai", "extra"]);
    assert_eq!(
        credentials[0].ticket,
        rasn::der::encode(&krb_cred.tickets[0]).expect("ticket encodes")
    );
    assert_eq!(
        credentials[1].ticket,
        rasn::der::encode(&krb_cred.tickets[1]).expect("ticket encodes")
    );
}

#[test]
fn decodes_decrypts_krb_cred_to_ccache_credentials() {
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");
    let krb_cred = encrypted_krb_cred(&enc_part);
    let bytes = rasn::der::encode(&krb_cred).expect("KRB-CRED encodes");
    let key = reply_key();

    let credentials = decode_decrypt_krb_cred_to_ccache_credentials(&bytes, &key)
        .expect("KRB-CRED bytes decode, decrypt, and convert");

    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].server.realm, "ATHENA.MIT.EDU");
    assert_eq!(credentials[1].times.end_time, TEST_TIME_SECONDS);
}

#[test]
fn rejects_krb_cred_ticket_info_count_mismatch() {
    let krb_cred = decode_krb_cred(&decode_hex(KRB_CRED)).expect("KRB-CRED decodes");
    let mut enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");
    enc_part.ticket_info.pop();

    let error = decrypted_krb_cred_to_ccache_credentials(&krb_cred, &enc_part)
        .expect_err("ticket-info count mismatch is rejected");

    assert!(matches!(
        error,
        Error::TicketInfoCountMismatch {
            ticket_count: 2,
            info_count: 1,
        }
    ));
}

#[test]
fn rejects_krb_cred_key_etype_mismatch() {
    let enc_part =
        decode_enc_krb_cred_part(&decode_hex(ENC_KRB_CRED_PART)).expect("EncKrbCredPart decodes");
    let krb_cred = encrypted_krb_cred(&enc_part);
    let key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error =
        decrypt_krb_cred_enc_part(&krb_cred, &key).expect_err("wrong key etype is rejected");

    assert!(matches!(
        error,
        Error::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        }
    ));
}

fn encrypted_krb_cred(enc_part: &rasn_kerberos::EncKrbCredPart) -> rasn_kerberos::KrbCred {
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("supported etype");
    let plaintext = rasn::der::encode(enc_part).expect("EncKrbCredPart encodes");
    let cipher = etype
        .encrypt_message_with_confounder(
            &key.value,
            &plaintext,
            KRB_CRED_ENCPART_USAGE,
            &decode_hex(CONFOUNDER),
        )
        .expect("KRB-CRED encrypted part encrypts");
    let fixture = decode_krb_cred(&decode_hex(KRB_CRED)).expect("KRB-CRED decodes");
    rasn_kerberos::KrbCred {
        pvno: Integer::from(5),
        msg_type: Integer::from(KRB_CRED_MSG_TYPE),
        tickets: fixture.tickets,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno: Some(7),
            cipher: cipher.into(),
        },
    }
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
