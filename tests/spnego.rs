#![cfg(feature = "spnego")]

use std::time::{Duration, UNIX_EPOCH};

use pretty_assertions::assert_eq;
use rskrb5::client::{AsRepSession, Principal};
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::{EncryptionKey, Keytab};
use rskrb5::service::{ApRepOptions, ServiceValidator};
use rskrb5::spnego::{
    self, CONTEXT_FLAG_CONF, CONTEXT_FLAG_INTEG, InitiatorContextOptions, Krb5MechToken,
    Krb5TokenId, NegState, NegTokenInit, NegTokenResp, NegotiationToken, ObjectIdentifier,
    SpnegoToken,
};

const KRB5_TOKEN: &str = concat!(
    "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea207030",
    "50000000000a382015d6182015930820155a003020105a10d1b0b544553542e474f4b524235",
    "a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235",
    "a382011830820114a003020112a103020103a28201060482010230621d868c97f30bf401e0",
    "3bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c015",
    "2f3996c45b1ea312a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460",
    "122ed97f363434e1e120b0e76c172b4424a536987152ac0b73013ab88af4b13a3fcdc",
    "63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d",
    "0424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327",
    "a0004aa8e19192726cf347561fa8ac74afad5d6a264e50cf495b93aac86c77b2bc2",
    "d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283ff32aa6a",
    "53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e",
    "420324f7edf9efae39df7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c",
    "50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bdbbd1fc40ac442195",
    "bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5",
    "f9815eef896a0c7e3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1",
    "a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6cb31ca363b1850d95c",
    "7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658",
);
const AUTH_CHECKSUM: &str = "100000000000000000000000000000000000000030000000";

const NEG_TOKEN_INIT: &str = concat!(
    "a08202aa308202a6a027302506092a864886f71201020206052b0501050206092a864882",
    "f71201020206062b0601050205a2820279048202756082027106092a864886f712010202",
    "01006e8202603082025ca003020105a10302010ea20703050000000000a38201706182",
    "016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103",
    "a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b308201",
    "27a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd676",
    "7abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d974",
    "0b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd",
    "4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066",
    "b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b87835",
    "6f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac",
    "4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589",
    "fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e",
    "1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9",
    "b64f41a481d23081cfa003020112a281c70481c4d67ba2ae4cf5d917caab1d863",
    "605249320e90482563662ed92408a543b6ad5edeb8f9375e9060a205491df082f",
    "d2a5fec93dfb76f41012bb60cae20f07adbb77a1aa56f0521f36e1ea10dc9f",
    "b762902b254dd7664d0bcc6f751f2003e41990af1b4330d10477bfad638b9f0b",
    "704ac80cc47731f8ec8d801762bad8884b8de90adb1dbe7fc7b0ffafd38fb5e",
    "b8b6547cee30d89873281ce63ad70042a13478b1a7c2bdde0f223ace62dbb84",
    "e2d06f1070f4265f66e0544449335e2fcc4d0aee5bf81c5999",
);
const NEG_TOKEN_RESP: &str = "a1143012a0030a0100a10b06092a864886f712010202";
const SPNEGO_INIT_PREFIX: &str = "608202b606062b0601050502";
const SPNEGO_RESP: &str = NEG_TOKEN_RESP;

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
const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const VALID_SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const AP_REP_RESPONSE_HEADER: &str = concat!(
    "Negotiate oXwweqADCgEAoQsGCSqGSIb3EgECAqJmBGRgYgYJKoZIhvcSAQICAgBvUzBRoAMCA",
    "QWhAwIBD6JFMEOgAwIBEqI8BDppQ8cwkzFMwZgOlePIcX3CimzQtTGRdViU5aDq1oZTFG",
    "9V/4+A4ZnQpz6O7l/4QbGdSdvItSIeIMNL",
);

#[test]
fn reports_gssapi_oids() {
    assert_eq!(
        ObjectIdentifier::krb5().arcs(),
        &[1, 2, 840, 113_554, 1, 2, 2]
    );
    assert_eq!(
        ObjectIdentifier::ms_legacy_krb5().arcs(),
        &[1, 2, 840, 48_018, 1, 2, 2]
    );
    assert_eq!(ObjectIdentifier::spnego().arcs(), &[1, 3, 6, 1, 5, 5, 2]);
}

#[test]
fn authenticator_checksum_matches_gokrb5() {
    assert_eq!(
        hex_encode(&spnego::authenticator_checksum(&[
            CONTEXT_FLAG_INTEG,
            CONTEXT_FLAG_CONF
        ])),
        AUTH_CHECKSUM
    );
}

#[test]
fn decodes_and_roundtrips_gokrb5_krb5_mech_token() {
    let bytes = decode_hex(KRB5_TOKEN);
    let token = Krb5MechToken::decode(&bytes).expect("KRB5 token decodes");

    assert_eq!(token.oid, ObjectIdentifier::krb5());
    assert_eq!(token.token_id, Krb5TokenId::ApReq);
    let ap_req = rskrb5::ap_req::decode_ap_req(&token.message).expect("AP-REQ decodes");
    assert_eq!(ap_req.msg_type, 14.into());
    assert_eq!(ap_req.authenticator.etype, 18);
    assert_eq!(
        hex_encode(&token.encode().expect("KRB5 token encodes")),
        KRB5_TOKEN
    );
}

#[test]
fn decodes_and_roundtrips_gokrb5_neg_token_init() {
    let bytes = decode_hex(NEG_TOKEN_INIT);
    let token = NegTokenInit::decode(&bytes).expect("NegTokenInit decodes");

    assert_eq!(token.mech_types.len(), 4);
    assert_eq!(token.mech_types[0], ObjectIdentifier::krb5());
    assert_eq!(token.mech_types[2], ObjectIdentifier::ms_legacy_krb5());
    assert!(
        token
            .mech_token
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        hex_encode(&token.encode().expect("NegTokenInit encodes")),
        NEG_TOKEN_INIT
    );
}

#[test]
fn decodes_and_roundtrips_gokrb5_neg_token_resp() {
    let bytes = decode_hex(NEG_TOKEN_RESP);
    let token = NegTokenResp::decode(&bytes).expect("NegTokenResp decodes");

    assert_eq!(token.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(token.supported_mech, Some(ObjectIdentifier::krb5()));
    assert_eq!(
        hex_encode(&token.encode().expect("NegTokenResp encodes")),
        NEG_TOKEN_RESP
    );
}

#[test]
fn decodes_and_roundtrips_full_spnego_tokens() {
    let spnego_init = format!("{SPNEGO_INIT_PREFIX}{NEG_TOKEN_INIT}");
    let init = SpnegoToken::decode(&decode_hex(&spnego_init)).expect("SPNEGO init decodes");
    let SpnegoToken::Init(init_token) = &init else {
        panic!("expected NegTokenInit");
    };
    assert_eq!(init_token.mech_types.len(), 4);
    assert!(!init_token.krb5_ap_req().expect("AP-REQ exists").is_empty());
    assert_eq!(
        hex_encode(&init.encode().expect("SPNEGO init encodes")),
        spnego_init
    );

    let resp = SpnegoToken::decode(&decode_hex(SPNEGO_RESP)).expect("SPNEGO resp decodes");
    let SpnegoToken::Resp(resp_token) = &resp else {
        panic!("expected NegTokenResp");
    };
    assert_eq!(resp_token.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(
        hex_encode(&resp.encode().expect("SPNEGO resp encodes")),
        SPNEGO_RESP
    );
}

#[test]
fn http_negotiate_helpers_match_gokrb5_headers() {
    let header = format!(
        "Negotiate {}",
        base64_encode(&decode_hex(&format!(
            "{SPNEGO_INIT_PREFIX}{NEG_TOKEN_INIT}"
        )))
    );
    let token = spnego::parse_negotiate_header(&header).expect("header parses");
    assert!(matches!(token, SpnegoToken::Init(_)));

    assert_eq!(spnego::challenge_header(), "Negotiate");
    assert_eq!(
        spnego::accept_completed_header().expect("accept header encodes"),
        "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
    );
    assert_eq!(
        spnego::accept_incomplete_krb5_header().expect("incomplete header encodes"),
        "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
    );
    assert_eq!(
        spnego::reject_header().expect("reject header encodes"),
        "Negotiate oQcwBaADCgEC"
    );
}

#[test]
fn http_negotiate_header_accepts_raw_krb5_ap_req_token() {
    let raw = decode_hex(KRB5_TOKEN);
    let header = format!("Negotiate {}", base64_encode(&raw));
    let parsed = spnego::parse_negotiate_header(&header).expect("raw KRB5 header parses");
    let krb5 = Krb5MechToken::decode(&raw).expect("raw KRB5 token decodes");

    assert!(matches!(parsed, SpnegoToken::Init(_)));
    assert_eq!(parsed.krb5_ap_req().expect("AP-REQ unwraps"), krb5.message);
}

#[test]
fn validates_service_ap_req_from_spnego_header_and_builds_ap_rep_response() {
    let ap_req_token = Krb5MechToken::ap_req(decode_hex(VALID_AP_REQ))
        .encode()
        .expect("KRB5 AP-REQ token encodes");
    let spnego_token = SpnegoToken::Init(NegTokenInit::krb5(ap_req_token));
    let header = spnego::negotiate_header(&spnego_token).expect("Negotiate header encodes");

    let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses");
    let mut validator =
        ServiceValidator::new(&keytab).with_now(UNIX_EPOCH + Duration::from_secs(1_893_553_447));
    let accepted = spnego::accept_sec_context_header(&mut validator, &header)
        .expect("SPNEGO AP-REQ validates");
    assert_eq!(accepted.ap_req.client.name(), "testuser1");

    let ap_rep_header = accepted
        .ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER),
            ApRepOptions::default(),
        )
        .expect("AP-REP response header encodes");
    assert_eq!(ap_rep_header, AP_REP_RESPONSE_HEADER);
    let response = spnego::parse_negotiate_header(&ap_rep_header).expect("AP-REP header parses");
    let SpnegoToken::Resp(resp) = response else {
        panic!("expected NegTokenResp");
    };
    let response_token = resp.response_token.expect("response token exists");
    let krb5 = Krb5MechToken::decode(&response_token).expect("KRB5 AP-REP token decodes");
    assert_eq!(krb5.token_id, Krb5TokenId::ApRep);
    accepted
        .ap_req
        .verify_ap_rep(&krb5.message)
        .expect("AP-REP verifies");
}

#[test]
fn builds_client_spnego_header_from_service_ticket() {
    let service_ticket = service_ticket_session_from_valid_ap_req();
    let context = spnego::init_sec_context_with_confounder(
        &service_ticket,
        InitiatorContextOptions::new().with_sequence_number(Some(42)),
        timestamp(1_893_553_447),
        123_456,
        &decode_hex(AP_REP_CONFOUNDER),
    )
    .expect("client SPNEGO context builds");

    assert_eq!(context.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(
        context.service,
        Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"])
    );
    assert_eq!(context.sequence_number, Some(42));

    let parsed = spnego::parse_negotiate_header(&context.header).expect("header parses");
    assert_eq!(parsed, context.spnego_token);
    assert_eq!(
        parsed.krb5_ap_req().expect("AP-REQ in SPNEGO"),
        context.ap_req_der
    );

    let ap_req: rasn_kerberos::ApReq =
        rasn::der::decode(&context.ap_req_der).expect("AP-REQ decodes");
    assert_eq!(ap_req.msg_type, 14.into());
    assert_eq!(ap_req.ap_options.0.as_raw_slice(), &[0, 0, 0, 0]);
    assert_eq!(ap_req.authenticator.etype, 18);

    let authenticator_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &service_ticket.session_key.value,
            ap_req.authenticator.cipher.as_ref(),
            11,
        )
        .expect("authenticator decrypts");
    let authenticator: rasn_kerberos::Authenticator =
        rasn::der::decode(&authenticator_bytes).expect("Authenticator decodes");
    let checksum = authenticator.cksum.expect("GSS checksum exists");
    assert_eq!(checksum.r#type, 32_771);
    assert_eq!(hex_encode(checksum.checksum.as_ref()), AUTH_CHECKSUM);
    assert_eq!(authenticator.seq_number, Some(42));

    let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses");
    let mut validator =
        ServiceValidator::new(&keytab).with_now(UNIX_EPOCH + Duration::from_secs(1_893_553_447));
    let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)
        .expect("client SPNEGO header validates");
    assert_eq!(accepted.ap_req.client.name(), "testuser1");
    assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
    assert_eq!(accepted.ap_req.sequence_number, Some(42));
}

#[test]
fn verifies_spnego_ap_rep_response_header_as_client() {
    let service_ticket = service_ticket_session_from_valid_ap_req();
    let context = spnego::init_sec_context_with_confounder(
        &service_ticket,
        InitiatorContextOptions::new().with_sequence_number(Some(42)),
        timestamp(1_893_553_447),
        123_456,
        &decode_hex(AP_REP_CONFOUNDER),
    )
    .expect("client SPNEGO context builds");
    let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses");
    let mut validator =
        ServiceValidator::new(&keytab).with_now(UNIX_EPOCH + Duration::from_secs(1_893_553_447));
    let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)
        .expect("client SPNEGO header validates");
    let response_header = accepted
        .ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER),
            ApRepOptions::default(),
        )
        .expect("AP-REP response header builds");

    let verified = context
        .verify_ap_rep_response_header(&response_header)
        .expect("client verifies AP-REP response header");

    assert_eq!(verified.ctime, context.authenticator_ctime);
    assert_eq!(verified.cusec, context.authenticator_cusec);
    assert_eq!(verified.authenticator_time, context.authenticator_time);
}

#[test]
fn negotiation_token_enum_roundtrips() {
    let init = NegotiationToken::decode(&decode_hex(NEG_TOKEN_INIT)).expect("init choice decodes");
    assert!(matches!(init, NegotiationToken::Init(_)));
    assert_eq!(
        hex_encode(&init.encode().expect("init choice encodes")),
        NEG_TOKEN_INIT
    );

    let resp = NegotiationToken::decode(&decode_hex(NEG_TOKEN_RESP)).expect("resp choice decodes");
    assert!(matches!(resp, NegotiationToken::Resp(_)));
    assert_eq!(
        hex_encode(&resp.encode().expect("resp choice encodes")),
        NEG_TOKEN_RESP
    );
}

fn service_ticket_session_from_valid_ap_req() -> AsRepSession {
    let ap_req: rasn_kerberos::ApReq =
        rasn::der::decode(&decode_hex(VALID_AP_REQ)).expect("AP-REQ fixture decodes");
    AsRepSession {
        client: Principal::user("TEST.GOKRB5", "testuser1"),
        service: Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
        session_key: EncryptionKey {
            etype: 18,
            value: decode_hex(VALID_SESSION_KEY),
        },
        ticket: rasn::der::encode(&ap_req.ticket).expect("ticket encodes"),
        ticket_flags: [0; 4],
        auth_time: timestamp(1_893_553_445),
        start_time: timestamp(1_893_553_445),
        end_time: timestamp(1_893_639_845),
        renew_till: None,
        key_expiration: None,
    }
}

fn timestamp(seconds: u64) -> std::time::SystemTime {
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

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
