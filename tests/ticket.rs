#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rasn::types::Integer;
use rskrb5::crypto::KerberosEtype;
use rskrb5::keytab::EncryptionKey;
use rskrb5::ticket::{
    Error, KDC_REP_TICKET_USAGE, KRB5_TKT_VNO, build_ticket, build_ticket_with_confounder,
    decode_enc_ticket_part, decode_ticket, decrypt_ticket_enc_part,
    encode_build_ticket_with_confounder, encode_ticket,
};

const MARSHALLED_TICKET: &str = concat!(
    "615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A",
    "3018A003020101A111300F1B066866747361691B056578747261A32530",
    "23A003020100A103020105A21704156B726241534E2E31207465737420",
    "6D657373616765",
);
const MARSHALLED_ENC_TICKET_PART: &str = concat!(
    "6382011430820110A007030500FEDCBA98A1133011A003020101A10A",
    "04083132333435363738A2101B0E415448454E412E4D49542E454455A3",
    "1A3018A003020101A111300F1B066866747361691B056578747261A42E",
    "302CA003020101A12504234544552C4D49542E2C415448454E412E2C",
    "57415348494E47544F4E2E4544552C43532EA511180F313939343036",
    "31303036303331375AA611180F31393934303631303036303331375AA7",
    "11180F31393934303631303036303331375AA811180F31393934303631",
    "303036303331375AA920301E300DA003020102A106040412D00023300D",
    "A003020102A106040412D00023AA243022300FA003020101A1080406",
    "666F6F626172300FA003020101A1080406666F6F626172",
);
const MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL: &str = concat!(
    "6381A53081A2A007030500FEDCBA98A1133011A003020101A10A04",
    "083132333435363738A2101B0E415448454E412E4D49542E454455A31A",
    "3018A003020101A111300F1B066866747361691B056578747261A42E",
    "302CA003020101A12504234544552C4D49542E2C415448454E412E2C",
    "57415348494E47544F4E2E4544552C43532EA511180F313939343036",
    "31303036303331375AA711180F31393934303631303036303331375A",
);
const TEST_TIME_SECONDS: i64 = 771_228_197;
const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

#[test]
fn decodes_gokrb5_ticket_fixture() {
    let bytes = decode_hex(MARSHALLED_TICKET);

    let ticket = decode_ticket(&bytes).expect("Ticket decodes");

    assert_eq!(ticket.tkt_vno, Integer::from(KRB5_TKT_VNO));
    assert_eq!(ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(ticket.sname.r#type, 1);
    assert_eq!(
        principal_components(&ticket.sname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    assert_eq!(ticket.enc_part.etype, 0);
    assert_eq!(ticket.enc_part.kvno, Some(5));
    assert_eq!(ticket.enc_part.cipher.as_ref(), b"krbASN.1 test message");
    assert_eq!(encode_ticket(&ticket).expect("Ticket encodes"), bytes);
}

#[test]
fn decodes_gokrb5_enc_ticket_part_fixture() {
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART))
        .expect("EncTicketPart decodes");

    assert_eq!(ticket_flags_to_bits(&enc_ticket.flags), 0xfedc_ba98);
    assert_eq!(enc_ticket.key.r#type, 1);
    assert_eq!(enc_ticket.key.value.as_ref(), b"12345678");
    assert_eq!(enc_ticket.crealm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(enc_ticket.cname.r#type, 1);
    assert_eq!(
        principal_components(&enc_ticket.cname),
        vec![b"hftsai".as_slice(), b"extra".as_slice()],
    );
    assert_eq!(enc_ticket.transited.r#type, 1);
    assert_eq!(
        enc_ticket.transited.contents.as_ref(),
        b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.",
    );
    assert_eq!(enc_ticket.auth_time.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(
        enc_ticket
            .start_time
            .as_ref()
            .expect("start time")
            .0
            .timestamp(),
        TEST_TIME_SECONDS,
    );
    assert_eq!(enc_ticket.end_time.0.timestamp(), TEST_TIME_SECONDS);
    assert_eq!(
        enc_ticket
            .renew_till
            .as_ref()
            .expect("renew till")
            .0
            .timestamp(),
        TEST_TIME_SECONDS,
    );
    let addresses = enc_ticket.caddr.as_ref().expect("addresses");
    assert_eq!(addresses.len(), 2);
    for address in addresses {
        assert_eq!(address.addr_type, 2);
        assert_eq!(address.address.as_ref(), decode_hex("12d00023"));
    }
    let auth_data = enc_ticket
        .authorization_data
        .as_ref()
        .expect("authorization data");
    assert_eq!(auth_data.len(), 2);
    for element in auth_data {
        assert_eq!(element.r#type, 1);
        assert_eq!(element.data.as_ref(), b"foobar");
    }
}

#[test]
fn decodes_gokrb5_enc_ticket_part_optionals_null_fixture() {
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL))
        .expect("EncTicketPart decodes");

    assert_eq!(ticket_flags_to_bits(&enc_ticket.flags), 0xfedc_ba98);
    assert_eq!(enc_ticket.key.r#type, 1);
    assert_eq!(enc_ticket.key.value.as_ref(), b"12345678");
    assert_eq!(enc_ticket.crealm.as_bytes(), b"ATHENA.MIT.EDU");
    assert_eq!(enc_ticket.cname.r#type, 1);
    assert_eq!(enc_ticket.auth_time.0.timestamp(), TEST_TIME_SECONDS);
    assert!(enc_ticket.start_time.is_none());
    assert_eq!(enc_ticket.end_time.0.timestamp(), TEST_TIME_SECONDS);
    assert!(enc_ticket.renew_till.is_none());
    assert!(enc_ticket.caddr.is_none());
    assert!(enc_ticket.authorization_data.is_none());
}

#[test]
fn builds_and_decrypts_ticket_with_explicit_confounder() {
    let fixture = decode_ticket(&decode_hex(MARSHALLED_TICKET)).expect("Ticket decodes");
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART))
        .expect("EncTicketPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x66; etype.confounder_len()];

    let ticket = build_ticket_with_confounder(
        fixture.realm.clone(),
        fixture.sname.clone(),
        &enc_ticket,
        &key,
        Some(3),
        &confounder,
    )
    .expect("Ticket builds");

    assert_eq!(ticket.tkt_vno, Integer::from(KRB5_TKT_VNO));
    assert_eq!(ticket.enc_part.etype, key.etype);
    assert_eq!(ticket.enc_part.kvno, Some(3));
    let decrypted = decrypt_ticket_enc_part(&ticket, &key).expect("ticket decrypts");
    assert_eq!(decrypted, enc_ticket);
}

#[test]
fn encodes_built_ticket_with_explicit_confounder() {
    let fixture = decode_ticket(&decode_hex(MARSHALLED_TICKET)).expect("Ticket decodes");
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL))
        .expect("EncTicketPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x77; etype.confounder_len()];

    let encoded = encode_build_ticket_with_confounder(
        fixture.realm,
        fixture.sname,
        &enc_ticket,
        &key,
        None,
        &confounder,
    )
    .expect("Ticket encodes");
    let decoded = decode_ticket(&encoded).expect("encoded Ticket decodes");

    assert_eq!(decoded.enc_part.etype, key.etype);
    assert!(decoded.enc_part.kvno.is_none());
    let decrypted = decrypt_ticket_enc_part(&decoded, &key).expect("ticket decrypts");
    assert_eq!(decrypted, enc_ticket);
}

#[test]
fn builds_and_decrypts_ticket_with_random_confounder() {
    let fixture = decode_ticket(&decode_hex(MARSHALLED_TICKET)).expect("Ticket decodes");
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART))
        .expect("EncTicketPart decodes");
    let key = reply_key();

    let ticket =
        build_ticket(fixture.realm, fixture.sname, &enc_ticket, &key, None).expect("Ticket builds");

    let decrypted = decrypt_ticket_enc_part(&ticket, &key).expect("ticket decrypts");
    assert_eq!(decrypted, enc_ticket);
}

#[test]
fn rejects_ticket_key_etype_mismatch() {
    let fixture = decode_ticket(&decode_hex(MARSHALLED_TICKET)).expect("Ticket decodes");
    let enc_ticket = decode_enc_ticket_part(&decode_hex(MARSHALLED_ENC_TICKET_PART))
        .expect("EncTicketPart decodes");
    let key = reply_key();
    let etype = KerberosEtype::from_etype_id(key.etype).expect("AES256 etype");
    let confounder = vec![0x66; etype.confounder_len()];
    let ticket = build_ticket_with_confounder(
        fixture.realm,
        fixture.sname,
        &enc_ticket,
        &key,
        None,
        &confounder,
    )
    .expect("Ticket builds");
    let wrong_key = EncryptionKey {
        etype: 17,
        value: vec![0; 16],
    };

    let error =
        decrypt_ticket_enc_part(&ticket, &wrong_key).expect_err("wrong etype key is rejected");

    assert!(matches!(
        error,
        Error::KeyEtypeMismatch {
            key_etype: 17,
            encrypted_data_etype: 18,
        }
    ));
}

#[test]
fn exposes_ticket_key_usage_constant() {
    assert_eq!(KDC_REP_TICKET_USAGE, 2);
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
