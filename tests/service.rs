#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::{EncryptionKey, Keytab};
use rskrb5::pac;
use rskrb5::service::{ApRepOptions, Error, Principal, ServiceValidator, ValidatedApReq};

mod common;

const HTTP_KEYTAB: &str = concat!(
    "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
);

const VALID_AP_REQ: &str = concat!(
    "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
    "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
    "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
    "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
    "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
    "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
    "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
    "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
    "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
    "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
    "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
    "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
    "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
    "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
);

const VALID_SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const PAC_TICKET_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const PAC_AUTHENTICATOR_CONFOUNDER: &str = "202122232425262728292a2b2c2d2e2f";
const KDC_REP_TICKET_USAGE_FOR_TEST: u32 = 2;
const AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST: u32 = 11;
const AP_REP_SERVER_SUBKEY: &str =
    "00112233445566778899aabbccddeeff102132435465768798a9babbdcddfeff";
const AP_REP_WITH_SUBKEY: &str = concat!(
    "6f818b308188a003020105a10302010fa27c307aa003020112a103020105a26e046c6943c730",
    "93314cc1980e95e3c8717dc2fe29c97f4305e55ac11912728f3b6c53f813e33f29188cc4b",
    "125596d747ac20c2d898c0a445ec50b12ec1c2870ac32b6fe2c0163de4b0c7c229cc63",
    "c80aa23a76914e6278f293a364dfaff666f374836bbd1209ceb97f9a17bd0fa2e",
);

const INVALID_TICKET_AP_REQ: &str = concat!(
    "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
    "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
    "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
    "389cd5b96595d2d1d8cebc6963a1c8fbb223c4a94b76f1369f10bf9c87d63c5514ff7b",
    "bb00bd28dd9804b6899e36af95f79ab3b0d85501bff6dded727cb67ad5a748f2ad3367",
    "1ff930910cdefccbaa1e108450a3e4ff6f9f263daf1a24f3073ffd7c5130fb7a192999",
    "c35315b96d09659f4921d573a7806bc3b70adcb3c5842a6c66ea46b0351889e8ad1b",
    "9007c29ff594aaade18be2cc893914de43062699cc3a8c407e0f001c88c2472bbb10f2",
    "6a1966f0984de309dd311a65359d520690a9ac9a267125fadc2ceed4e46be0bf151fd",
    "b4295e3d37933bba481ab3081a8a003020112a103020101a2819b0481980e807bcf2123",
    "ba5724d8ab08fc2fd96e3c21793ca1c15d1565bc5ce2e42e2016430d7601bf49a1a7",
    "c40546749242f1ec56c8ae16a7498d4925dca885bceb4a3b5b8de02bb99a967060d",
    "4e7cf3d3b0666dcafa3a6c36287aeb99a9fa0279c20bb988763276a3da6f306a827",
    "b53e2868f560a3b71b7047e5630b19074a4176fd8c29c49cc039dd53b158771a93c",
    "a2ebe8ee42fde2c060fb2d1",
);

const BADMATCH_AP_REQ: &str = concat!(
    "6e8201f7308201f3a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
    "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
    "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
    "8256b413abf60f64f76692684a3cbedff3822acc4bc9edf1ca36f085828520de09ae593",
    "971e02ff706b9ab985436f516734009bd02a557cea8648a66c3106c37567f5c1c1b77620",
    "6e452d348c65ced2e3dccd22bebdc9f86f48c1543cea7c8125ae839490cf3361d762b",
    "9e206da0fa2da25e8381f525f5e0383aba2139a44d563b16da14c8bc12b83b096ee35",
    "5051e201f96d76fe8c01fa81db7a10a90b446229f1a10f047d889ca1696d01a3867d5",
    "7652fb3870ba07f7b7eafdf00b939784cce3d15e932640f9a0358939c2640befba0f",
    "3efcf9de18268ba481aa3081a7a003020112a103020101a2819a048197d80b4b768e13fd5a",
    "b024375e464e5a99beab36169a48fc33abb129c21db948c7b2c0c28a1ac0ef7540cf",
    "5109a5efdb45da8a7bf2cb57356da2d052b0d79fa49149c6928bcb1572b2e31c1",
    "f6019aa27c74e3691c2716a0ec72042624316e3f4c98e73fac734ce397101a6b2b49",
    "41fa20afc16f3f0845a6b7e1e9b25054cb02bd95fb97db781020cb5a6cf5ee81314",
    "0c6183e5483650d1e9",
);

#[test]
fn validates_gokrb5_ap_req_fixture() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));

    let validated = validator
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("AP-REQ validates");

    assert_eq!(
        validated.client,
        Principal {
            realm: "TEST.GOKRB5".to_owned(),
            name_type: 1,
            components: vec!["testuser1".to_owned()],
        }
    );
    assert_eq!(validated.client.name(), "testuser1");
    assert_eq!(
        validated.service,
        Principal {
            realm: "TEST.GOKRB5".to_owned(),
            name_type: 1,
            components: vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()],
        }
    );
    assert_eq!(validated.session_key.etype, 18);
    assert_eq!(hex_encode(&validated.session_key.value), VALID_SESSION_KEY);
    assert_eq!(validated.subkey.expect("subkey exists").etype, 18);
    assert_eq!(validated.sequence_number, Some(42));
    assert_eq!(validated.ticket_start, timestamp(1_893_553_445));
    assert_eq!(validated.ticket_end, timestamp(1_893_639_845));
    assert_eq!(validated.authenticator_ctime, timestamp(1_893_553_447));
    assert_eq!(validated.authenticator_cusec, 123_456);
    assert_eq!(
        validated.authenticator_time,
        timestamp(1_893_553_447) + Duration::from_micros(123_456)
    );
    assert!(validated.pac.is_none());
}

#[test]
fn validates_ap_req_with_verified_ticket_pac() {
    let keytab = syshttp_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));

    let validated = validator
        .validate_ap_req(&ap_req_with_pac())
        .expect("AP-REQ with PAC validates");

    assert_eq!(validated.client.name(), "testuser1");
    assert_eq!(validated.service.name(), "sysHTTP");
    assert_eq!(validated.session_key.etype, 18);
    assert_eq!(hex_encode(&validated.session_key.value), VALID_SESSION_KEY);
    let pac = validated.pac.as_ref().expect("PAC extracted and verified");
    assert_eq!(pac.c_buffers, 5);
    assert_eq!(
        pac.kerb_validation_info
            .as_ref()
            .expect("KVI parsed")
            .effective_name
            .value,
        "testuser1"
    );
    assert_eq!(
        pac.upn_dns_info.as_ref().expect("UPN/DNS parsed").upn,
        "testuser1@test.gokrb5"
    );
}

#[test]
fn rejects_ap_req_with_invalid_ticket_pac_checksum() {
    let keytab = syshttp_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let mut pac_bytes = decode_hex(common::PAC_AD_WIN2K);
    let pac_header = pac::Pac::parse(&pac_bytes).expect("PAC header parses");
    let server_signature = pac_header
        .buffer(pac::INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
        .expect("server checksum buffer exists");
    let signature_offset = usize::try_from(server_signature.offset).expect("offset fits") + 4;
    pac_bytes[signature_offset] ^= 0x01;

    assert!(matches!(
        validator
            .validate_ap_req(&ap_req_with_pac_bytes(pac_bytes))
            .expect_err("bad PAC checksum is rejected"),
        Error::Pac(pac::Error::ServerChecksumVerificationFailed)
    ));
}

#[test]
fn builds_and_verifies_ap_rep_mutual_auth_reply() {
    let validated = valid_ap_req();
    let options = ap_rep_options();

    let ap_rep = validated
        .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER), options.clone())
        .expect("AP-REP builds");
    assert_eq!(hex_encode(&ap_rep), AP_REP_WITH_SUBKEY);
    let verified = validated.verify_ap_rep(&ap_rep).expect("AP-REP verifies");

    assert_eq!(verified.ctime, validated.authenticator_ctime);
    assert_eq!(verified.cusec, validated.authenticator_cusec);
    assert_eq!(verified.authenticator_time, validated.authenticator_time);
    assert_eq!(verified.subkey, options.subkey);
    assert_eq!(verified.sequence_number, options.sequence_number);
}

#[test]
fn rejects_ap_rep_timestamp_mismatch() {
    let validated = valid_ap_req();
    let ap_rep = validated
        .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER), ApRepOptions::default())
        .expect("AP-REP builds");
    let mut wrong_request = validated.clone();
    wrong_request.authenticator_cusec += 1;
    wrong_request.authenticator_time += Duration::from_micros(1);

    assert!(matches!(
        wrong_request
            .verify_ap_rep(&ap_rep)
            .expect_err("mismatched AP-REP timestamp rejected"),
        Error::ApRepTimestampMismatch { .. }
    ));
}

#[test]
fn rejects_tampered_ap_rep() {
    let validated = valid_ap_req();
    let mut ap_rep = validated
        .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER), ApRepOptions::default())
        .expect("AP-REP builds");
    let last = ap_rep.last_mut().expect("AP-REP is non-empty");
    *last ^= 0x01;

    assert!(matches!(
        validated
            .verify_ap_rep(&ap_rep)
            .expect_err("tampered AP-REP rejected"),
        Error::Crypto(rskrb5::crypto::Error::IntegrityCheckFailed)
    ));
}

#[test]
fn detects_ap_req_replay() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    validator
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("first AP-REQ validates");

    assert!(matches!(
        validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("second AP-REQ is replay"),
        Error::Replay
    ));

    validator.replay_cache_mut().clear();
    validator
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("cleared replay cache permits request");
}

#[test]
fn clears_old_replay_cache_entries() {
    let keytab = http_keytab();
    let now = timestamp(1_893_553_447);
    let mut validator = ServiceValidator::new(&keytab).with_now(now);
    validator
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("first AP-REQ validates");
    assert_eq!(validator.replay_cache_mut().len(), 1);

    let removed = validator.replay_cache_mut().clear_older_than_at(
        Duration::from_secs(5 * 60),
        now.checked_add(Duration::from_secs(5 * 60 + 1))
            .expect("cleanup time"),
    );

    assert_eq!(removed, 1);
    assert!(validator.replay_cache_mut().is_empty());
    validator
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("expired replay entry no longer rejects request");
}

#[test]
fn validates_keytab_principal_override_failure() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .with_keytab_principal(["foo"]);

    assert!(matches!(
        validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("wrong service principal key is rejected"),
        Error::Keytab(_)
    ));
}

#[test]
fn rejects_client_principal_mismatch() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));

    assert!(matches!(
        validator
            .validate_ap_req(&decode_hex(BADMATCH_AP_REQ))
            .expect_err("client mismatch rejected"),
        Error::ClientPrincipalMismatch { .. }
    ));
}

#[test]
fn rejects_invalid_future_and_expired_tickets() {
    let keytab = http_keytab();
    let mut invalid_validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    assert!(matches!(
        invalid_validator
            .validate_ap_req(&decode_hex(INVALID_TICKET_AP_REQ))
            .expect_err("invalid ticket rejected"),
        Error::TicketNotYetValid { .. }
    ));

    let mut future_validator =
        ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_445 - 301));
    assert!(matches!(
        future_validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("future ticket rejected"),
        Error::TicketNotYetValid { .. }
    ));

    let mut expired_validator =
        ServiceValidator::new(&keytab).with_now(timestamp(1_893_639_845 + 301));
    assert!(matches!(
        expired_validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("expired ticket rejected"),
        Error::TicketExpired { .. }
    ));
}

#[test]
fn rejects_large_authenticator_clock_skew() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447 + 301));

    assert!(matches!(
        validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("authenticator skew rejected"),
        Error::ClockSkew { .. }
    ));
}

#[test]
fn rejects_addressless_ticket_when_client_address_is_required() {
    let keytab = http_keytab();
    let mut validator = ServiceValidator::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .require_client_address(true);

    assert!(matches!(
        validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ))
            .expect_err("addressless ticket rejected"),
        Error::RequiredClientAddressMissing { .. }
    ));
}

fn http_keytab() -> Keytab {
    Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses")
}

fn syshttp_keytab() -> Keytab {
    Keytab::parse(&decode_hex(common::SYSHTTP_KEYTAB)).expect("sysHTTP keytab parses")
}

fn ap_req_with_pac() -> Vec<u8> {
    ap_req_with_pac_bytes(decode_hex(common::PAC_AD_WIN2K))
}

fn ap_req_with_pac_bytes(pac_bytes: Vec<u8>) -> Vec<u8> {
    let keytab = syshttp_keytab();
    let (service_key, _) = keytab
        .find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)
        .expect("sysHTTP service key exists");
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(VALID_SESSION_KEY),
    };
    let client = principal(["testuser1"]);
    let service = principal(["sysHTTP"]);
    let pac_authorization_data = pac_authorization_data(pac_bytes);
    let auth_time = kerberos_time(1_893_553_445);
    let ctime = kerberos_time(1_893_553_447);

    let enc_ticket = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(zero_kerberos_flags()),
        key: encryption_key(&session_key),
        crealm: realm("TEST.GOKRB5"),
        cname: client.clone(),
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time: auth_time.clone(),
        start_time: Some(auth_time),
        end_time: kerberos_time(1_893_639_845),
        renew_till: None,
        caddr: None,
        authorization_data: Some(pac_authorization_data),
    };
    let ticket_cipher = encrypt_message(
        service_key,
        &rasn::der::encode(&enc_ticket).expect("EncTicketPart encodes"),
        KDC_REP_TICKET_USAGE_FOR_TEST,
        PAC_TICKET_CONFOUNDER,
    );

    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: 5.into(),
        crealm: realm("TEST.GOKRB5"),
        cname: client,
        cksum: None,
        cusec: 123_456.into(),
        ctime,
        subkey: None,
        seq_number: Some(42),
        authorization_data: None,
    };
    let authenticator_cipher = encrypt_message(
        &session_key,
        &rasn::der::encode(&authenticator).expect("Authenticator encodes"),
        AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST,
        PAC_AUTHENTICATOR_CONFOUNDER,
    );

    let ap_req = rasn_kerberos::ApReq {
        pvno: 5.into(),
        msg_type: 14.into(),
        ap_options: rasn_kerberos::ApOptions(zero_kerberos_flags()),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: 5.into(),
            realm: realm("TEST.GOKRB5"),
            sname: service,
            enc_part: rasn_kerberos::EncryptedData {
                etype: service_key.etype,
                kvno: Some(2),
                cipher: ticket_cipher.into(),
            },
        },
        authenticator: rasn_kerberos::EncryptedData {
            etype: session_key.etype,
            kvno: None,
            cipher: authenticator_cipher.into(),
        },
    };

    rasn::der::encode(&ap_req).expect("AP-REQ encodes")
}

fn pac_authorization_data(pac_bytes: Vec<u8>) -> rasn_kerberos::AuthorizationData {
    let nested =
        rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
            r#type: pac::AD_WIN2K_PAC,
            data: pac_bytes.into(),
        }]);
    let nested_der = rasn::der::encode(&nested).expect("nested authorization-data encodes");
    rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
        r#type: pac::AD_IF_RELEVANT,
        data: nested_der.into(),
    }])
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

fn encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype,
        value: key.value.clone().into(),
    }
}

fn principal<const N: usize>(components: [&str; N]) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: 1,
        string: components.into_iter().map(kerberos_string).collect(),
    }
}

fn realm(value: &str) -> rasn_kerberos::Realm {
    kerberos_string(value)
}

fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .expect("Kerberos string uses permitted characters")
}

fn kerberos_time(seconds: u64) -> rasn_kerberos::KerberosTime {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0)
        .expect("fixture timestamp is representable");
    let offset = chrono::FixedOffset::east_opt(0).expect("UTC offset exists");
    rasn_kerberos::KerberosTime(utc.with_timezone(&offset))
}

fn zero_kerberos_flags() -> rasn_kerberos::KerberosFlags {
    rasn_kerberos::KerberosFlags::repeat(false, 32)
}

fn valid_ap_req() -> ValidatedApReq {
    let keytab = http_keytab();
    ServiceValidator::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .validate_ap_req(&decode_hex(VALID_AP_REQ))
        .expect("AP-REQ validates")
}

fn ap_rep_options() -> ApRepOptions {
    ApRepOptions {
        subkey: Some(EncryptionKey {
            etype: 18,
            value: decode_hex(AP_REP_SERVER_SUBKEY),
        }),
        sequence_number: Some(17),
        kvno: Some(5),
    }
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
