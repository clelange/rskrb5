#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::client::{
    AS_REP_ENCPART_USAGE, AS_REQ_PA_ENC_TIMESTAMP_USAGE, AsReqOptions, BuiltAsReq, Error,
    KDC_ERR_PREAUTH_REQUIRED, KdcTransport, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_REQ_ENC_PA_REP,
    PreauthKeyInfo, Principal, build_tgt_as_req, default_password_salt, derive_password_reply_key,
    exchange_as_req, login_tgt_with_keytab, login_tgt_with_password,
    pa_enc_timestamp_with_confounder, process_as_rep, process_kdc_error, select_preauth_key_info,
};
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const PREAUTH_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const AS_REP_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TICKET_FLAGS: &[u8; 4] = &[0x40, 0x81, 0x00, 0x10];
const TESTUSER_PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER_SALT: &str = "TEST.GOKRB5testuser1";

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

#[test]
fn parses_kdc_preauth_required_error_and_selects_etype_info2() {
    let error_bytes = synthetic_preauth_required_error();

    let error = process_kdc_error(&error_bytes).expect("KRB-ERROR decodes");

    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    assert_eq!(
        error.client,
        Some(Principal::user("TEST.GOKRB5", "testuser1"))
    );
    assert_eq!(error.service, Principal::tgt_service("TEST.GOKRB5"));
    assert_eq!(error.method_data.len(), 1);
    assert_eq!(
        error.preauth_key_info,
        vec![PreauthKeyInfo {
            etype: 18,
            salt: Some(TESTUSER_SALT.to_owned()),
            s2kparams: Some(vec![0, 0, 16, 0]),
        }]
    );

    let selected = select_preauth_key_info(&error, &[17, 18]).expect("supported hint is selected");
    assert_eq!(selected.etype, 18);
    assert_eq!(
        default_password_salt(&Principal::user("TEST.GOKRB5", "testuser1")),
        TESTUSER_SALT
    );
}

#[test]
fn login_tgt_with_password_retries_after_preauth_required() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_etypes(vec![18]);
    let key_info = password_key_info();
    let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
        .expect("password key derives");
    let mut transport = PreauthTransport::new(reply_key, None);

    let session =
        login_tgt_with_password(&mut transport, client.clone(), TESTUSER_PASSWORD, options)
            .expect("password login succeeds");

    assert_eq!(transport.calls, 2);
    assert_eq!(session.client, client);
    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
}

#[test]
fn login_tgt_with_keytab_retries_with_selected_keytab_kvno() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_etypes(vec![18]);
    let keytab = keytab_with_reply_key(7);
    let mut transport = PreauthTransport::new(reply_key(), Some(7));

    let session = login_tgt_with_keytab(&mut transport, client.clone(), &keytab, options)
        .expect("keytab login succeeds");

    assert_eq!(transport.calls, 2);
    assert_eq!(session.client, client);
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

struct PreauthTransport {
    reply_key: EncryptionKey,
    expected_pa_kvno: Option<u32>,
    calls: usize,
}

impl PreauthTransport {
    fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
        Self {
            reply_key,
            expected_pa_kvno,
            calls: 0,
        }
    }
}

impl KdcTransport for PreauthTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::AsReq = rasn::der::decode(request).expect("AS-REQ decodes");
        self.calls += 1;
        match self.calls {
            1 => {
                let padata = decoded.0.padata.as_ref().expect("initial probe has padata");
                assert_eq!(padata.len(), 1);
                assert_eq!(padata[0].r#type, PA_REQ_ENC_PA_REP);
                assert!(padata[0].value.as_ref().is_empty());
                Ok(synthetic_preauth_required_error())
            }
            2 => {
                assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno);
                let built = built_request_from_der(decoded, request);
                Ok(synthetic_as_rep_with_reply_key(
                    &built,
                    built.nonce,
                    built.service.clone(),
                    &self.reply_key,
                ))
            }
            _ => panic!("unexpected transport call {}", self.calls),
        }
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
    synthetic_as_rep_with_reply_key(request, nonce, ticket_service, &reply_key())
}

fn synthetic_as_rep_with_reply_key(
    request: &BuiltAsReq,
    nonce: u32,
    ticket_service: Principal,
    reply_key: &EncryptionKey,
) -> Vec<u8> {
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
        reply_key,
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

fn synthetic_preauth_required_error() -> Vec<u8> {
    let etype_info2 = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
        etype: 18,
        salt: Some(kerberos_string(TESTUSER_SALT)),
        s2kparams: Some(vec![0, 0, 16, 0].into()),
    }]);
    let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
        r#type: PA_ETYPE_INFO2,
        value: rasn::der::encode(&etype_info2)
            .expect("ETYPE-INFO2 encodes")
            .into(),
    }]);
    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: KDC_ERR_PREAUTH_REQUIRED,
        crealm: Some(realm("TEST.GOKRB5")),
        cname: Some(rasn_principal(&Principal::user("TEST.GOKRB5", "testuser1"))),
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&Principal::tgt_service("TEST.GOKRB5")),
        e_text: Some(kerberos_string("Additional pre-authentication required")),
        e_data: Some(
            rasn::der::encode(&method_data)
                .expect("METHOD-DATA encodes")
                .into(),
        ),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

fn password_key_info() -> PreauthKeyInfo {
    PreauthKeyInfo {
        etype: 18,
        salt: Some(TESTUSER_SALT.to_owned()),
        s2kparams: Some(vec![0, 0, 16, 0]),
    }
}

fn keytab_with_reply_key(kvno: u32) -> Keytab {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(KeytabEntry {
        principal: KeytabPrincipal {
            realm: "TEST.GOKRB5".to_owned(),
            components: vec!["testuser1".to_owned()],
            name_type: 1,
        },
        timestamp: 1_893_553_440,
        kvno8: kvno as u8,
        key: reply_key(),
        kvno,
    });
    keytab
}

fn assert_pa_enc_timestamp(request: &rasn_kerberos::AsReq, expected_kvno: Option<u32>) {
    let padata = request.0.padata.as_ref().expect("second AS-REQ has padata");
    let pa_enc_timestamp = padata
        .iter()
        .find(|padata| padata.r#type == PA_ENC_TIMESTAMP)
        .expect("second AS-REQ has PA-ENC-TIMESTAMP");
    let encrypted: rasn_kerberos::EncryptedData =
        rasn::der::decode(pa_enc_timestamp.value.as_ref()).expect("encrypted timestamp decodes");
    assert_eq!(encrypted.etype, 18);
    assert_eq!(encrypted.kvno, expected_kvno);
    assert!(!encrypted.cipher.as_ref().is_empty());
}

fn built_request_from_der(message: rasn_kerberos::AsReq, der: &[u8]) -> BuiltAsReq {
    let body = &message.0.req_body;
    let client = principal_from_parts(&body.realm, body.cname.as_ref().expect("cname"));
    let service = principal_from_parts(&body.realm, body.sname.as_ref().expect("sname"));
    BuiltAsReq {
        nonce: body.nonce,
        message,
        der: der.to_vec(),
        client,
        service,
    }
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
