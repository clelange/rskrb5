#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::client::{
    AS_REP_ENCPART_USAGE, AS_REQ_PA_ENC_TIMESTAMP_USAGE, AsReqOptions, BuiltAsReq, Error,
    KdcTransport, PA_ENC_TIMESTAMP, Principal, build_tgt_as_req, exchange_as_req,
    pa_enc_timestamp_with_confounder, process_as_rep,
};
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::EncryptionKey;

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const PREAUTH_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const AS_REP_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TICKET_FLAGS: &[u8; 4] = &[0x40, 0x81, 0x00, 0x10];

#[test]
fn builds_tgt_as_req_with_expected_fields() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_ticket_lifetime(Duration::from_secs(8 * 60 * 60))
        .with_etypes(vec![18, 17]);

    let request = build_tgt_as_req(client.clone(), options).expect("AS-REQ builds");
    let decoded: rasn_kerberos::AsReq = rasn::der::decode(&request.der).expect("AS-REQ decodes");

    assert_eq!(request.message, decoded);
    assert_eq!(decoded.0.pvno, rasn::types::Integer::from(5));
    assert_eq!(decoded.0.msg_type, rasn::types::Integer::from(10));
    assert!(decoded.0.padata.is_none());

    let body = &decoded.0.req_body;
    assert_eq!(
        principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
        client
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        Principal::tgt_service("TEST.GOKRB5")
    );
    assert_eq!(
        system_time_from_kerberos_time(&body.till),
        timestamp(1_893_582_247)
    );
    assert!(body.rtime.is_none());
    assert_eq!(body.nonce, 0x1122_3344);
    assert_eq!(body.etype, vec![18, 17]);
    assert!(body.addresses.is_none());
    assert!(body.enc_authorization_data.is_none());
    assert!(body.additional_tickets.is_none());
}

#[test]
fn builds_and_encrypts_pa_enc_timestamp() {
    let key = reply_key();
    let padata = pa_enc_timestamp_with_confounder(
        &key,
        timestamp(1_893_553_447),
        123_456,
        &decode_hex(PREAUTH_CONFOUNDER),
        Some(7),
    )
    .expect("PA-ENC-TIMESTAMP builds");

    assert_eq!(padata.r#type, PA_ENC_TIMESTAMP);
    let encrypted: rasn_kerberos::EncryptedData =
        rasn::der::decode(padata.value.as_ref()).expect("encrypted timestamp decodes");
    assert_eq!(encrypted.etype, 18);
    assert_eq!(encrypted.kvno, Some(7));

    let plaintext = AesSha1Etype::Aes256
        .decrypt_message(
            &key.value,
            encrypted.cipher.as_ref(),
            AS_REQ_PA_ENC_TIMESTAMP_USAGE,
        )
        .expect("encrypted timestamp decrypts");
    let timestamp_part: rasn_kerberos::PaEncTsEnc =
        rasn::der::decode(&plaintext).expect("PA-ENC-TS-ENC decodes");

    assert_eq!(
        system_time_from_kerberos_time(&timestamp_part.patimestamp),
        timestamp(1_893_553_447)
    );
    assert_eq!(
        timestamp_part
            .pausec
            .expect("microseconds")
            .to_string()
            .parse::<u32>()
            .expect("microseconds parse"),
        123_456
    );
}

#[test]
fn processes_as_rep_and_exports_ccache_credential() {
    let request = sample_request();
    let reply_key = reply_key();
    let response = synthetic_as_rep(&request, request.nonce);

    let session = process_as_rep(&request, &response, &reply_key).expect("AS-REP validates");

    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
    assert_eq!(session.session_key.etype, 18);
    assert_eq!(hex_encode(&session.session_key.value), SESSION_KEY);
    assert_eq!(session.ticket_flags, *TICKET_FLAGS);
    assert_eq!(session.auth_time, timestamp(1_893_553_445));
    assert_eq!(session.start_time, timestamp(1_893_553_445));
    assert_eq!(session.end_time, timestamp(1_893_639_845));
    assert_eq!(session.renew_till, Some(timestamp(1_894_071_845)));

    let ticket: rasn_kerberos::Ticket = rasn::der::decode(&session.ticket).expect("ticket decodes");
    assert_eq!(ticket.tkt_vno, rasn::types::Integer::from(5));

    let credential = session
        .to_ccache_credential()
        .expect("ccache credential converts");
    assert_eq!(credential.client.realm, "TEST.GOKRB5");
    assert_eq!(credential.client.components, vec!["testuser1"]);
    assert_eq!(credential.server.components, vec!["krbtgt", "TEST.GOKRB5"]);
    assert_eq!(credential.key.value, decode_hex(SESSION_KEY));
    assert_eq!(credential.times.auth_time, 1_893_553_445);
    assert_eq!(credential.times.end_time, 1_893_639_845);
    assert_eq!(credential.times.renew_till, 1_894_071_845);
    assert_eq!(credential.ticket, session.ticket);
    assert!(credential.second_ticket.is_empty());
}

#[test]
fn rejects_as_rep_nonce_mismatch() {
    let request = sample_request();
    let response = synthetic_as_rep(&request, request.nonce + 1);

    let error =
        process_as_rep(&request, &response, &reply_key()).expect_err("nonce mismatch fails");

    assert!(matches!(
        error,
        Error::NonceMismatch {
            expected: 0x1122_3344,
            actual: 0x1122_3345,
        }
    ));
}

#[test]
fn rejects_as_rep_ticket_service_mismatch() {
    let request = sample_request();
    let response = synthetic_as_rep_with_ticket_service(
        &request,
        request.nonce,
        Principal::tgt_service("BAD.REALM"),
    );

    let error =
        process_as_rep(&request, &response, &reply_key()).expect_err("service mismatch fails");

    assert!(matches!(
        error,
        Error::ServicePrincipalMismatch {
            expected,
            actual,
        } if expected == "krbtgt/TEST.GOKRB5" && actual == "krbtgt/BAD.REALM"
    ));
}

#[test]
fn exchange_as_req_uses_transport_boundary() {
    let request = sample_request();
    let response = synthetic_as_rep(&request, request.nonce);
    let mut transport = MockTransport {
        expected_realm: "TEST.GOKRB5".to_owned(),
        expected_request: request.der.clone(),
        response,
        called: false,
    };

    let session =
        exchange_as_req(&mut transport, &request, &reply_key()).expect("transport exchange works");

    assert!(transport.called);
    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
}

struct MockTransport {
    expected_realm: String,
    expected_request: Vec<u8>,
    response: Vec<u8>,
    called: bool,
}

impl KdcTransport for MockTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, self.expected_realm);
        assert_eq!(request, self.expected_request.as_slice());
        self.called = true;
        Ok(self.response.clone())
    }
}

fn sample_request() -> BuiltAsReq {
    build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344),
    )
    .expect("sample request builds")
}

fn synthetic_as_rep(request: &BuiltAsReq, nonce: u32) -> Vec<u8> {
    synthetic_as_rep_with_ticket_service(request, nonce, request.service.clone())
}

fn synthetic_as_rep_with_ticket_service(
    request: &BuiltAsReq,
    nonce: u32,
    ticket_service: Principal,
) -> Vec<u8> {
    let reply_key = reply_key();
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SESSION_KEY),
    };
    let enc_part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_encryption_key(&session_key),
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(1_893_553_445),
        }],
        nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(TICKET_FLAGS)),
        auth_time: kerberos_time(1_893_553_445),
        start_time: Some(kerberos_time(1_893_553_445)),
        end_time: kerberos_time(1_893_639_845),
        renew_till: Some(kerberos_time(1_894_071_845)),
        srealm: realm(&request.service.realm),
        sname: rasn_principal(&request.service),
        caddr: None,
        encrypted_pa_data: None,
    });
    let encrypted = encrypt_message(
        &reply_key,
        &rasn::der::encode(&enc_part).expect("EncAsRepPart encodes"),
        AS_REP_ENCPART_USAGE,
        AS_REP_CONFOUNDER,
    );
    let as_rep = rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(11),
        padata: None,
        crealm: realm(&request.client.realm),
        cname: rasn_principal(&request.client),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: rasn::types::Integer::from(5),
            realm: realm(&ticket_service.realm),
            sname: rasn_principal(&ticket_service),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: [0xde, 0xad, 0xbe, 0xef].as_slice().into(),
            },
        },
        enc_part: rasn_kerberos::EncryptedData {
            etype: reply_key.etype,
            kvno: Some(3),
            cipher: encrypted.into(),
        },
    });
    rasn::der::encode(&as_rep).expect("AS-REP encodes")
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: decode_hex(REPLY_KEY),
    }
}

fn rasn_encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype,
        value: key.value.clone().into(),
    }
}

fn encrypt_message(
    key: &EncryptionKey,
    plaintext: &[u8],
    usage: u32,
    confounder_hex: &str,
) -> Vec<u8> {
    let etype = AesSha1Etype::from_etype_id(key.etype).expect("AES-SHA1 etype is supported");
    etype
        .encrypt_message_with_confounder(&key.value, plaintext, usage, &decode_hex(confounder_hex))
        .expect("message encrypts")
}

fn rasn_principal(value: &Principal) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: value.name_type,
        string: value
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect(),
    }
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Principal {
    Principal::new(
        kerberos_string_to_string(realm),
        name.r#type,
        name.string.iter().map(kerberos_string_to_string),
    )
}

fn realm(value: &str) -> rasn_kerberos::Realm {
    kerberos_string(value)
}

fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .expect("Kerberos string uses permitted characters")
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> String {
    std::str::from_utf8(value.as_bytes())
        .expect("Kerberos string is UTF-8")
        .to_owned()
}

fn kerberos_time(seconds: u64) -> rasn_kerberos::KerberosTime {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0)
        .expect("fixture timestamp is representable");
    let offset = chrono::FixedOffset::east_opt(0).expect("UTC offset exists");
    rasn_kerberos::KerberosTime(utc.with_timezone(&offset))
}

fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> SystemTime {
    UNIX_EPOCH + Duration::new(time.0.timestamp() as u64, time.0.timestamp_subsec_nanos())
}

fn timestamp(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
