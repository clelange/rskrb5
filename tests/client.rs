#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
#[cfg(feature = "tokio")]
use rskrb5::ccache;
use rskrb5::client::{
    AP_REQ_AUTHENTICATOR_USAGE, AS_REP_ENCPART_USAGE, AS_REQ_PA_ENC_TIMESTAMP_USAGE, ApReqOptions,
    AsReqOptions, BuiltAsReq, BuiltTgsReq, Error, KDC_ERR_PREAUTH_REQUIRED, KDC_OPTION_RENEW,
    KDC_OPTION_RENEWABLE, KdcError, KdcTransport, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2,
    PA_REQ_ENC_PA_REP, PA_TGS_REQ, PreauthKeyInfo, Principal, TGS_REP_ENCPART_SESSION_KEY_USAGE,
    TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE, TGS_REQ_AUTHENTICATOR_USAGE, TgsReqOptions,
    build_ap_req_with_confounder, build_tgs_req_for_realm_with_confounder,
    build_tgs_req_with_confounder, build_tgt_as_req, build_tgt_renewal_req_with_confounder,
    build_ticket_renewal_req_with_confounder, default_password_salt, derive_password_reply_key,
    exchange_as_req, exchange_tgs_req, login_tgt_with_keytab, login_tgt_with_password,
    pa_enc_timestamp_with_confounder, process_as_rep, process_kdc_error, process_tgs_rep,
    process_tgs_rep_with_referral, renew_tgt, renew_ticket, select_preauth_key_info,
};
#[cfg(feature = "tokio")]
use rskrb5::client::{KdcProtocol, TokioClient};
#[cfg(feature = "tokio")]
use rskrb5::config::Config;
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const SERVICE_SESSION_KEY: &str =
    "7b4115955ac25c69929af6b55c47a81db574cbbf615647e385ea38a58e2a7e9a";
const PREAUTH_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const AS_REP_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TGS_REQ_CONFOUNDER: &str = "202122232425262728292a2b2c2d2e2f";
const TGS_REP_CONFOUNDER: &str = "303132333435363738393a3b3c3d3e3f";
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
fn builds_tgt_as_req_with_renew_lifetime_sets_renewable_flag() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_ticket_lifetime(Duration::from_secs(8 * 60 * 60))
        .with_renew_lifetime(Some(Duration::from_secs(10 * 60 * 60)));

    let request = build_tgt_as_req(client, options).expect("AS-REQ builds");
    let decoded: rasn_kerberos::AsReq = rasn::der::decode(&request.der).expect("AS-REQ decodes");
    let body = &decoded.0.req_body;

    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        KDC_OPTION_RENEWABLE.to_be_bytes().as_slice()
    );
    assert_eq!(
        system_time_from_kerberos_time(body.rtime.as_ref().expect("renew time")),
        timestamp(1_893_589_447)
    );
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
fn process_as_rep_surfaces_kdc_error_response() {
    let request = sample_request();
    let error = process_as_rep(&request, &synthetic_preauth_required_error(), &reply_key())
        .expect_err("KRB-ERROR response is surfaced");

    assert!(matches!(
        error,
        Error::Kdc(kdc_error) if kdc_error.error_code == KDC_ERR_PREAUTH_REQUIRED
    ));
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
fn builds_tgs_req_with_pa_tgs_req_and_checksum() {
    let tgt = sample_tgt_session();
    let service = sample_service_principal();
    let options = TgsReqOptions::new(timestamp(1_893_553_450), 0x5566_7788)
        .with_ticket_lifetime(Duration::from_secs(2 * 60 * 60))
        .with_etypes(vec![18]);

    let request = build_tgs_req_with_confounder(
        &tgt,
        service.clone(),
        options,
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");

    assert_eq!(request.message, decoded);
    assert_eq!(decoded.0.pvno, rasn::types::Integer::from(5));
    assert_eq!(decoded.0.msg_type, rasn::types::Integer::from(12));

    let body = &decoded.0.req_body;
    assert_eq!(
        principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
        tgt.client
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        service
    );
    assert_eq!(
        system_time_from_kerberos_time(&body.till),
        timestamp(1_893_560_650)
    );
    assert!(body.rtime.is_none());
    assert_eq!(body.nonce, 0x5566_7788);
    assert_eq!(body.etype, vec![18]);

    let padata = decoded.0.padata.as_ref().expect("TGS-REQ has padata");
    assert_eq!(padata.len(), 1);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
    let ap_req: rasn_kerberos::ApReq =
        rasn::der::decode(padata[0].value.as_ref()).expect("PA-TGS-REQ AP-REQ decodes");
    assert_eq!(ap_req.pvno, rasn::types::Integer::from(5));
    assert_eq!(ap_req.msg_type, rasn::types::Integer::from(14));
    assert_eq!(ap_req.ap_options.0.as_raw_slice(), &[0, 0, 0, 0]);
    let tgt_ticket: rasn_kerberos::Ticket =
        rasn::der::decode(&tgt.ticket).expect("TGT ticket decodes");
    assert_eq!(ap_req.ticket, tgt_ticket);
    assert_eq!(ap_req.authenticator.etype, 18);
    assert_eq!(ap_req.authenticator.kvno, Some(2));

    let authenticator_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &tgt.session_key.value,
            ap_req.authenticator.cipher.as_ref(),
            TGS_REQ_AUTHENTICATOR_USAGE,
        )
        .expect("TGS authenticator decrypts");
    let authenticator: rasn_kerberos::Authenticator =
        rasn::der::decode(&authenticator_bytes).expect("Authenticator decodes");
    assert_eq!(
        principal_from_parts(&authenticator.crealm, &authenticator.cname),
        tgt.client
    );
    assert_eq!(
        authenticator
            .cusec
            .to_string()
            .parse::<u32>()
            .expect("cusec"),
        654_321
    );
    assert_eq!(
        system_time_from_kerberos_time(&authenticator.ctime),
        timestamp(1_893_553_451)
    );
    let checksum = authenticator.cksum.expect("authenticator has checksum");
    assert_eq!(checksum.r#type, AesSha1Etype::Aes256.checksum_type_id());
    let body_der = rasn::der::encode(body).expect("TGS-REQ-BODY encodes");
    assert!(AesSha1Etype::Aes256.verify_checksum(
        &tgt.session_key.value,
        &body_der,
        checksum.checksum.as_ref(),
        TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
    ));
}

#[test]
fn builds_tgs_req_for_explicit_kdc_realm() {
    let tgt = sample_tgt_session();
    let service = Principal::new("RESDOM.GOKRB5", 2, ["HTTP", "host.resdom.gokrb5"]);
    let request = build_tgs_req_for_realm_with_confounder(
        &tgt,
        "TEST.GOKRB5",
        service.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x4455_6677).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");

    assert_eq!(request.kdc_realm, "TEST.GOKRB5");
    assert_eq!(request.service, service);
    assert_eq!(
        kerberos_string_to_string(&decoded.0.req_body.realm),
        "TEST.GOKRB5"
    );
    assert_eq!(
        principal_from_parts(
            &realm("RESDOM.GOKRB5"),
            decoded.0.req_body.sname.as_ref().expect("sname")
        ),
        service
    );
}

#[test]
fn builds_service_ap_req_with_subkey_and_sequence_number() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let subkey = EncryptionKey {
        etype: 18,
        value: vec![0x44; 32],
    };
    let options = ApReqOptions::new()
        .with_ap_option_bits(0x2000_0000)
        .with_subkey(Some(subkey.clone()))
        .with_sequence_number(Some(42));

    let built = build_ap_req_with_confounder(
        &service_ticket,
        options,
        timestamp(1_893_553_452),
        456_789,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("AP-REQ builds");
    let decoded: rasn_kerberos::ApReq = rasn::der::decode(&built.der).expect("AP-REQ decodes");

    assert_eq!(built.message, decoded);
    assert_eq!(built.client, service_ticket.client);
    assert_eq!(built.service, service_ticket.service);
    assert_eq!(built.sequence_number, Some(42));
    assert_eq!(built.subkey, Some(subkey.clone()));
    assert_eq!(decoded.pvno, rasn::types::Integer::from(5));
    assert_eq!(decoded.msg_type, rasn::types::Integer::from(14));
    assert_eq!(
        decoded.ap_options.0.as_raw_slice(),
        0x2000_0000u32.to_be_bytes().as_slice()
    );
    assert_eq!(
        decoded.authenticator.etype,
        service_ticket.session_key.etype
    );

    let authenticator_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &service_ticket.session_key.value,
            decoded.authenticator.cipher.as_ref(),
            AP_REQ_AUTHENTICATOR_USAGE,
        )
        .expect("AP-REQ authenticator decrypts");
    let authenticator: rasn_kerberos::Authenticator =
        rasn::der::decode(&authenticator_bytes).expect("Authenticator decodes");

    assert_eq!(
        principal_from_parts(&authenticator.crealm, &authenticator.cname),
        service_ticket.client
    );
    assert!(authenticator.cksum.is_none());
    assert_eq!(authenticator.seq_number, Some(42));
    let decoded_subkey = authenticator.subkey.expect("authenticator subkey");
    assert_eq!(decoded_subkey.r#type, subkey.etype);
    assert_eq!(decoded_subkey.value.as_ref(), subkey.value.as_slice());
    assert_eq!(
        authenticator
            .cusec
            .to_string()
            .parse::<u32>()
            .expect("cusec"),
        456_789
    );
    assert_eq!(
        system_time_from_kerberos_time(&authenticator.ctime),
        timestamp(1_893_553_452)
    );
}

#[test]
fn builds_tgt_renewal_req_sets_renew_options() {
    let tgt = sample_tgt_session();
    let request = build_tgt_renewal_req_with_confounder(
        &tgt,
        TgsReqOptions::new(timestamp(1_893_553_450), 0x7788_99aa)
            .with_kdc_option_bits(0x0000_0010)
            .with_renew_lifetime(Some(Duration::from_secs(10 * 60 * 60)))
            .with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("TGT renewal TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");
    let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;

    assert_eq!(request.kdc_realm, "TEST.GOKRB5");
    assert_eq!(request.service, Principal::tgt_service("TEST.GOKRB5"));
    let body = &decoded.0.req_body;
    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        expected_options.to_be_bytes().as_slice()
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        Principal::tgt_service("TEST.GOKRB5")
    );
    assert_eq!(
        system_time_from_kerberos_time(body.rtime.as_ref().expect("renew time")),
        timestamp(1_893_589_450)
    );
}

#[test]
fn builds_ticket_renewal_req_sets_service_and_renew_options() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let request = build_ticket_renewal_req_with_confounder(
        &service_ticket,
        TgsReqOptions::new(timestamp(1_893_553_450), 0x8877_6655)
            .with_kdc_option_bits(0x0000_0010)
            .with_renew_lifetime(Some(Duration::from_secs(10 * 60 * 60)))
            .with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("service-ticket renewal TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");
    let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;

    assert_eq!(request.kdc_realm, "TEST.GOKRB5");
    assert_eq!(request.service, sample_service_principal());
    let body = &decoded.0.req_body;
    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        expected_options.to_be_bytes().as_slice()
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        sample_service_principal()
    );
    assert_eq!(
        system_time_from_kerberos_time(body.rtime.as_ref().expect("renew time")),
        timestamp(1_893_589_450)
    );
}

#[test]
fn processes_tgs_rep_and_exports_ccache_credential() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);

    let session =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");

    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, sample_service_principal());
    assert_eq!(session.session_key.etype, 18);
    assert_eq!(hex_encode(&session.session_key.value), SERVICE_SESSION_KEY);
    assert_eq!(session.ticket_flags, *TICKET_FLAGS);
    assert_eq!(session.auth_time, timestamp(1_893_553_445));
    assert_eq!(session.start_time, timestamp(1_893_553_446));
    assert_eq!(session.end_time, timestamp(1_893_560_646));
    assert_eq!(session.renew_till, Some(timestamp(1_894_071_846)));

    let credential = session
        .to_ccache_credential()
        .expect("ccache credential converts");
    assert_eq!(credential.client.components, vec!["testuser1"]);
    assert_eq!(
        credential.server.components,
        vec!["HTTP", "host.test.gokrb5"]
    );
    assert_eq!(credential.key.value, decode_hex(SERVICE_SESSION_KEY));
    assert_eq!(credential.times.auth_time, 1_893_553_445);
    assert_eq!(credential.times.start_time, 1_893_553_446);
    assert_eq!(credential.times.end_time, 1_893_560_646);
    assert!(!credential.ticket.is_empty());
}

#[test]
fn process_tgs_rep_surfaces_kdc_error_response() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let error = process_tgs_rep(
        &request,
        &synthetic_preauth_required_error(),
        &tgt.session_key,
    )
    .expect_err("KRB-ERROR response is surfaced");

    assert!(matches!(
        error,
        Error::Kdc(kdc_error) if kdc_error.error_code == KDC_ERR_PREAUTH_REQUIRED
    ));
}

#[test]
fn process_tgs_rep_with_referral_accepts_intermediate_tgt() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let referral = Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"]);
    let response =
        synthetic_tgs_rep_with_service(&request, request.nonce, &tgt.session_key, referral.clone());

    let strict = process_tgs_rep(&request, &response, &tgt.session_key)
        .expect_err("strict TGS-REP validation rejects referrals");
    assert!(matches!(strict, Error::ServicePrincipalMismatch { .. }));

    let session = process_tgs_rep_with_referral(&request, &response, &tgt.session_key)
        .expect("referral TGS-REP validates");
    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, referral);
    assert_eq!(session.session_key.etype, 18);
    assert!(!session.ticket.is_empty());
}

#[test]
fn exchange_tgs_req_uses_transport_boundary() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let mut transport = MockTransport {
        expected_realm: "TEST.GOKRB5".to_owned(),
        expected_request: request.der.clone(),
        response,
        called: false,
    };

    let session = exchange_tgs_req(&mut transport, &request, &tgt.session_key)
        .expect("transport exchange works");

    assert!(transport.called);
    assert_eq!(session.service, sample_service_principal());
}

#[test]
fn renew_tgt_uses_transport_boundary() {
    let tgt = sample_tgt_session();
    let mut transport = RenewalTransport {
        session_key: tgt.session_key.clone(),
        expected_service: Principal::tgt_service("TEST.GOKRB5"),
        calls: 0,
    };

    let session = renew_tgt(
        &mut transport,
        &tgt,
        TgsReqOptions::new(timestamp(1_893_553_450), 0x6677_8899).with_etypes(vec![18]),
    )
    .expect("TGT renewal succeeds");

    assert_eq!(transport.calls, 1);
    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
    assert!(!session.ticket.is_empty());
}

#[test]
fn renew_ticket_uses_transport_boundary() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut transport = RenewalTransport {
        session_key: service_ticket.session_key.clone(),
        expected_service: sample_service_principal(),
        calls: 0,
    };

    let session = renew_ticket(
        &mut transport,
        &service_ticket,
        TgsReqOptions::new(timestamp(1_893_553_450), 0x7766_5544).with_etypes(vec![18]),
    )
    .expect("service-ticket renewal succeeds");

    assert_eq!(transport.calls, 1);
    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, sample_service_principal());
    assert!(!session.ticket.is_empty());
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_returns_cached_service_ticket_from_ccache() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    let mut service_credential = service_ticket
        .to_ccache_credential()
        .expect("service ticket converts");
    make_credential_current(&mut service_credential, now);
    cache.credentials_mut().push(tgt_credential);
    cache.credentials_mut().push(service_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let returned = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect("cached service ticket is returned");

    assert_eq!(
        client.tgt_session().expect("TGT loaded").service,
        tgt.service
    );
    assert_eq!(client.cached_service_ticket_count(), 1);
    assert_eq!(returned.client, service_ticket.client);
    assert_eq!(returned.service, service_ticket.service);
    assert_eq!(returned.session_key, service_ticket.session_key);
    assert_eq!(returned.ticket, service_ticket.ticket);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_ignores_other_client_credentials() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let default_client = ccache::Principal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]);
    let other_client = ccache::Principal::new("OTHER.REALM", 1, vec!["other".to_owned()]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;
    let mut cache = ccache::CCache::new(default_client.clone());

    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    let mut service_credential = service_ticket
        .to_ccache_credential()
        .expect("service ticket converts");
    make_credential_current(&mut service_credential, now);

    let mut other_tgt = tgt_credential.clone();
    other_tgt.client = other_client.clone();
    other_tgt.server = ccache::Principal::new(
        "OTHER.REALM",
        2,
        vec!["krbtgt".to_owned(), "OTHER.REALM".to_owned()],
    );
    other_tgt.key.value = vec![0xee];
    other_tgt.times.end_time = now + 2 * 60 * 60;
    other_tgt.times.renew_till = now + 3 * 60 * 60;

    let mut other_service = service_credential.clone();
    other_service.client = other_client;
    other_service.server = ccache::Principal::new(
        "OTHER.REALM",
        2,
        vec!["HTTP".to_owned(), "other.test.gokrb5".to_owned()],
    );
    other_service.key.value = vec![0xdd];

    cache.credentials_mut().push(other_tgt);
    cache
        .credentials_mut()
        .push(x_cacheconf_credential(&default_client));
    cache.credentials_mut().push(tgt_credential);
    cache.credentials_mut().push(other_service);
    cache.credentials_mut().push(service_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let returned = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect("default client's cached service ticket is returned");
    let loaded_tgt = client.tgt_session().expect("TGT loaded");

    assert_eq!(client.client_principal(), &tgt.client);
    assert_eq!(loaded_tgt.client, tgt.client);
    assert_eq!(loaded_tgt.service, tgt.service);
    assert_eq!(loaded_tgt.session_key, tgt.session_key);
    assert_eq!(client.cached_service_ticket_count(), 1);
    assert_eq!(returned.session_key, service_ticket.session_key);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_keeps_freshest_duplicate_service_ticket() {
    let tgt = sample_tgt_session();
    let mut fresh_service_ticket = sample_service_ticket_session(&tgt);
    let mut older_service_ticket = fresh_service_ticket.clone();
    fresh_service_ticket.session_key.value = vec![0xf1];
    fresh_service_ticket.ticket = b"fresh-service-ticket".to_vec();
    older_service_ticket.session_key.value = vec![0x0d];
    older_service_ticket.ticket = b"older-service-ticket".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    let mut fresh_credential = fresh_service_ticket
        .to_ccache_credential()
        .expect("fresh service ticket converts");
    make_credential_current(&mut fresh_credential, now);
    fresh_credential.times.end_time = now + 2 * 60 * 60;
    let mut older_credential = older_service_ticket
        .to_ccache_credential()
        .expect("older service ticket converts");
    make_credential_current(&mut older_credential, now);
    older_credential.times.end_time = now + 60;

    cache.credentials_mut().push(tgt_credential);
    cache.credentials_mut().push(fresh_credential);
    cache.credentials_mut().push(older_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let returned = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect("freshest cached service ticket is returned");

    assert_eq!(client.cached_service_ticket_count(), 1);
    assert_eq!(returned.session_key, fresh_service_ticket.session_key);
    assert_eq!(returned.ticket, fresh_service_ticket.ticket);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_prefers_current_tgt_over_future_duplicate() {
    let mut current_tgt = sample_tgt_session();
    let mut future_tgt = current_tgt.clone();
    current_tgt.session_key.value = vec![0xc1];
    future_tgt.session_key.value = vec![0xf1];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut current_credential = current_tgt
        .to_ccache_credential()
        .expect("current TGT converts");
    make_credential_current(&mut current_credential, now);
    current_credential.times.end_time = now + 60 * 60;
    let mut future_credential = future_tgt
        .to_ccache_credential()
        .expect("future TGT converts");
    future_credential.times.auth_time = now;
    future_credential.times.start_time = now + 60;
    future_credential.times.end_time = now + 2 * 60 * 60;
    future_credential.times.renew_till = now + 3 * 60 * 60;

    cache.credentials_mut().push(current_credential);
    cache.credentials_mut().push(future_credential);

    let client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let loaded_tgt = client.tgt_session().expect("TGT loaded");

    assert_eq!(loaded_tgt.session_key, current_tgt.session_key);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_login_returns_current_cache_only_tgt() {
    let tgt = sample_tgt_session();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    cache.credentials_mut().push(tgt_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let session = runtime()
        .block_on(client.login())
        .expect("current cache-only TGT is returned");

    assert_eq!(session.client, tgt.client);
    assert_eq!(session.service, tgt.service);
    assert_eq!(session.session_key, tgt.session_key);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_exposes_assume_preauthentication_setting() {
    let client = TokioClient::with_password(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
        TESTUSER_PASSWORD,
    )
    .with_assume_preauthentication(true);

    assert!(client.assume_preauthentication());
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_login_rejects_expired_cache_only_tgt() {
    let tgt = sample_tgt_session();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_expired(&mut tgt_credential, now);
    cache.credentials_mut().push(tgt_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let error = runtime()
        .block_on(client.login())
        .expect_err("expired cache-only TGT is not returned");

    assert!(matches!(error, Error::NoClientCredentials));
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_prefers_current_service_ticket_over_future_duplicate() {
    let tgt = sample_tgt_session();
    let mut current_service_ticket = sample_service_ticket_session(&tgt);
    let mut future_service_ticket = current_service_ticket.clone();
    current_service_ticket.session_key.value = vec![0xc2];
    current_service_ticket.ticket = b"current-service-ticket".to_vec();
    future_service_ticket.session_key.value = vec![0xf2];
    future_service_ticket.ticket = b"future-service-ticket".to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    let mut current_credential = current_service_ticket
        .to_ccache_credential()
        .expect("current service ticket converts");
    make_credential_current(&mut current_credential, now);
    current_credential.times.end_time = now + 60 * 60;
    let mut future_credential = future_service_ticket
        .to_ccache_credential()
        .expect("future service ticket converts");
    future_credential.times.auth_time = now;
    future_credential.times.start_time = now + 60;
    future_credential.times.end_time = now + 2 * 60 * 60;
    future_credential.times.renew_till = now + 3 * 60 * 60;

    cache.credentials_mut().push(tgt_credential);
    cache.credentials_mut().push(current_credential);
    cache.credentials_mut().push(future_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let returned = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect("current cached service ticket is returned");

    assert_eq!(client.cached_service_ticket_count(), 1);
    assert_eq!(returned.session_key, current_service_ticket.session_key);
    assert_eq!(returned.ticket, current_service_ticket.ticket);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_rejects_expired_tgt_without_live_credentials() {
    let tgt = sample_tgt_session();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_expired(&mut tgt_credential, now);
    cache.credentials_mut().push(tgt_credential);

    let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    let error = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect_err("expired cache-only TGT cannot acquire a service ticket");

    assert!(matches!(error, Error::NoClientCredentials));
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_from_ccache_rejects_expired_service_ticket() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_secs() as u32;

    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "TEST.GOKRB5",
        1,
        vec!["testuser1".to_owned()],
    ));
    let mut tgt_credential = tgt.to_ccache_credential().expect("TGT converts");
    make_credential_current(&mut tgt_credential, now);
    let mut service_credential = service_ticket
        .to_ccache_credential()
        .expect("service ticket converts");
    make_credential_expired(&mut service_credential, now);
    cache.credentials_mut().push(tgt_credential);
    cache.credentials_mut().push(service_credential);

    let mut client = TokioClient::from_ccache(config_without_kdcs(), KdcProtocol::Tcp, &cache);
    let error = runtime()
        .block_on(client.get_service_ticket(sample_service_principal()))
        .expect_err("expired service ticket is not returned from cache");

    assert!(matches!(
        error,
        Error::NoKdcEndpoints {
            realm,
            protocol: KdcProtocol::Tcp,
        } if realm == "TEST.GOKRB5"
    ));
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_exports_and_saves_ccache() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket.clone());

    let cache = client.to_ccache().expect("client exports ccache");
    assert_eq!(cache.default_principal().realm, "TEST.GOKRB5");
    assert_eq!(cache.default_principal().components, ["testuser1"]);
    assert_eq!(cache.entries().len(), 2);
    assert!(cache.contains_server(&["krbtgt", "TEST.GOKRB5"]));
    assert!(cache.contains_server(&["HTTP", "host.test.gokrb5"]));

    let reloaded = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    assert_eq!(reloaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(reloaded.cached_service_ticket_count(), 1);

    let path = temp_client_ccache_file("export-save");
    client.save_ccache(&path).expect("client saves ccache");
    let loaded = ccache::CCache::load(&path).expect("saved ccache loads");
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded, cache);
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_json_snapshots_match_gokrb5_shapes() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket);

    let sessions = client.sessions_json().expect("sessions JSON renders");
    assert_eq!(
        sessions,
        r#"[
  {
    "Realm": "TEST.GOKRB5",
    "AuthTime": "2030-01-02T03:04:05Z",
    "EndTime": "2030-01-03T03:04:05Z",
    "RenewTill": "2030-01-08T03:04:05Z",
    "SessionKeyExpiration": "2030-01-03T03:04:05Z"
  }
]"#
    );

    let service_tickets = client
        .service_ticket_cache_json()
        .expect("service-ticket cache JSON renders");
    assert_eq!(
        service_tickets,
        r#"[
  {
    "SPN": "HTTP/host.test.gokrb5",
    "AuthTime": "2030-01-02T03:04:05Z",
    "StartTime": "2030-01-02T03:04:06Z",
    "EndTime": "2030-01-02T05:04:06Z",
    "RenewTill": "2030-01-08T03:04:06Z"
  }
]"#
    );
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_updates_ccache_file_without_duplicate_tickets() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket.clone());

    let mut old_tgt = tgt.to_ccache_credential().expect("TGT converts");
    old_tgt.client.name_type = 0;
    old_tgt.key.value = vec![0xaa];
    let mut old_service = service_ticket
        .to_ccache_credential()
        .expect("service ticket converts");
    old_service.client.name_type = 0;
    old_service.key.value = vec![0xbb];
    let config_entry = x_cacheconf_credential(&old_service.client);
    let mut other_client = old_service.clone();
    other_client.client = ccache::Principal::new("OTHER.REALM", 1, vec!["other".to_owned()]);
    other_client.server = ccache::Principal::new(
        "OTHER.REALM",
        2,
        vec!["HTTP".to_owned(), "other".to_owned()],
    );

    let mut existing = ccache::CCache::new(old_tgt.client.clone());
    existing.credentials_mut().push(old_tgt);
    existing.credentials_mut().push(config_entry.clone());
    existing.credentials_mut().push(old_service);
    existing.credentials_mut().push(other_client.clone());

    let path = temp_client_ccache_file("update-file");
    existing.save(&path).expect("existing ccache saves");
    client
        .update_ccache_file(&path)
        .expect("client updates ccache file");
    let updated = ccache::CCache::load(&path).expect("updated ccache loads");
    let _ = std::fs::remove_file(&path);

    assert_eq!(updated.default_principal().components, ["testuser1"]);
    assert_eq!(
        updated
            .credentials()
            .iter()
            .filter(|credential| credential.client == config_entry.client
                && credential.server.components == ["krb5_ccache_conf_data", "fast_avail"])
            .count(),
        1
    );
    assert!(updated.credentials().contains(&other_client));
    assert_eq!(
        matching_credentials(
            &updated,
            &ccache::Principal::new(
                "TEST.GOKRB5",
                2,
                vec!["krbtgt".to_owned(), "TEST.GOKRB5".to_owned()]
            )
        )
        .len(),
        1
    );
    assert_eq!(
        matching_credentials(
            &updated,
            &ccache::Principal::new(
                "TEST.GOKRB5",
                2,
                vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()]
            )
        )
        .len(),
        1
    );
    assert_eq!(
        updated
            .get_entry(&["krbtgt", "TEST.GOKRB5"])
            .expect("updated TGT exists")
            .key
            .value,
        tgt.session_key.value
    );
    assert_eq!(
        updated
            .get_entry(&["HTTP", "host.test.gokrb5"])
            .expect("updated service ticket exists")
            .key
            .value,
        service_ticket.session_key.value
    );
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
fn selects_and_derives_rc4_hmac_preauth_key_info() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let error = KdcError {
        error_code: KDC_ERR_PREAUTH_REQUIRED,
        text: None,
        client: Some(client.clone()),
        service: Principal::tgt_service("TEST.GOKRB5"),
        e_data: None,
        method_data: Vec::new(),
        preauth_key_info: vec![PreauthKeyInfo {
            etype: 23,
            salt: Some("ignored-by-rc4".to_owned()),
            s2kparams: None,
        }],
    };

    let selected = select_preauth_key_info(&error, &[18, 23]).expect("RC4 hint is selected");
    assert_eq!(selected.etype, 23);

    let reply_key =
        derive_password_reply_key(&client, b"foo", &selected).expect("RC4 reply key derives");
    assert_eq!(reply_key.etype, 23);
    assert_eq!(
        reply_key.value,
        decode_hex("ac8e657f83df82beea5d43bdaf7800cc")
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
fn login_tgt_with_password_can_assume_preauthentication() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_etypes(vec![18])
        .with_assume_preauthentication(true);
    let key_info = PreauthKeyInfo {
        etype: 18,
        salt: None,
        s2kparams: None,
    };
    let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
        .expect("password key derives");
    let mut transport = AssumedPreauthTransport::new(reply_key, None);

    let session =
        login_tgt_with_password(&mut transport, client.clone(), TESTUSER_PASSWORD, options)
            .expect("password login succeeds");

    assert_eq!(transport.calls, 1);
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

#[test]
fn login_tgt_with_keytab_can_assume_preauthentication() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_etypes(vec![20, 18])
        .with_assume_preauthentication(true);
    let keytab = keytab_with_reply_key(3);
    let mut transport = AssumedPreauthTransport::new(reply_key(), Some(3));

    let session = login_tgt_with_keytab(&mut transport, client.clone(), &keytab, options)
        .expect("keytab login succeeds");

    assert_eq!(transport.calls, 1);
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

struct RenewalTransport {
    session_key: EncryptionKey,
    expected_service: Principal,
    calls: usize,
}

impl KdcTransport for RenewalTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::TgsReq = rasn::der::decode(request).expect("TGS-REQ decodes");
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            (KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW)
                .to_be_bytes()
                .as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
            self.expected_service
        );

        self.calls += 1;
        let built = built_tgs_request_from_der(decoded, request);
        Ok(synthetic_tgs_rep(
            &built,
            built.nonce,
            &self.session_key.clone(),
        ))
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

struct AssumedPreauthTransport {
    reply_key: EncryptionKey,
    expected_pa_kvno: Option<u32>,
    calls: usize,
}

impl AssumedPreauthTransport {
    fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
        Self {
            reply_key,
            expected_pa_kvno,
            calls: 0,
        }
    }
}

impl KdcTransport for AssumedPreauthTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::AsReq = rasn::der::decode(request).expect("AS-REQ decodes");
        self.calls += 1;
        assert_eq!(self.calls, 1, "assumed preauth should only call KDC once");

        let padata = decoded
            .0
            .padata
            .as_ref()
            .expect("assumed preauth request has padata");
        assert!(
            padata
                .iter()
                .any(|padata| padata.r#type == PA_REQ_ENC_PA_REP),
            "assumed preauth keeps PA-REQ-ENC-PA-REP"
        );
        assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno);

        let built = built_request_from_der(decoded, request);
        Ok(synthetic_as_rep_with_reply_key(
            &built,
            built.nonce,
            built.service.clone(),
            &self.reply_key,
        ))
    }
}

fn sample_request() -> BuiltAsReq {
    build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344),
    )
    .expect("sample request builds")
}

fn sample_tgt_session() -> rskrb5::client::AsRepSession {
    let request = sample_request();
    let response = synthetic_as_rep(&request, request.nonce);
    process_as_rep(&request, &response, &reply_key()).expect("sample TGT validates")
}

fn sample_tgs_request(tgt: &rskrb5::client::AsRepSession) -> BuiltTgsReq {
    build_tgs_req_with_confounder(
        tgt,
        sample_service_principal(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x5566_7788).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("sample TGS-REQ builds")
}

fn sample_service_principal() -> Principal {
    Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
}

#[cfg(feature = "tokio")]
fn sample_service_ticket_session(
    tgt: &rskrb5::client::AsRepSession,
) -> rskrb5::client::TgsRepSession {
    let request = sample_tgs_request(tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates")
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

fn synthetic_tgs_rep(
    request: &BuiltTgsReq,
    nonce: u32,
    tgs_session_key: &EncryptionKey,
) -> Vec<u8> {
    synthetic_tgs_rep_with_service(request, nonce, tgs_session_key, request.service.clone())
}

fn synthetic_tgs_rep_with_service(
    request: &BuiltTgsReq,
    nonce: u32,
    tgs_session_key: &EncryptionKey,
    reply_service: Principal,
) -> Vec<u8> {
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SERVICE_SESSION_KEY),
    };
    let enc_part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_encryption_key(&session_key),
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(1_893_553_445),
        }],
        nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(TICKET_FLAGS)),
        auth_time: kerberos_time(1_893_553_445),
        start_time: Some(kerberos_time(1_893_553_446)),
        end_time: kerberos_time(1_893_560_646),
        renew_till: Some(kerberos_time(1_894_071_846)),
        srealm: realm(&reply_service.realm),
        sname: rasn_principal(&reply_service),
        caddr: None,
        encrypted_pa_data: None,
    });
    let encrypted = encrypt_message(
        tgs_session_key,
        &rasn::der::encode(&enc_part).expect("EncTgsRepPart encodes"),
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
        TGS_REP_CONFOUNDER,
    );
    let tgs_rep = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(13),
        padata: None,
        crealm: realm(&request.client.realm),
        cname: rasn_principal(&request.client),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: rasn::types::Integer::from(5),
            realm: realm(&reply_service.realm),
            sname: rasn_principal(&reply_service),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(4),
                cipher: [0xca, 0xfe, 0xba, 0xbe].as_slice().into(),
            },
        },
        enc_part: rasn_kerberos::EncryptedData {
            etype: tgs_session_key.etype,
            kvno: None,
            cipher: encrypted.into(),
        },
    });
    rasn::der::encode(&tgs_rep).expect("TGS-REP encodes")
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

fn built_tgs_request_from_der(message: rasn_kerberos::TgsReq, der: &[u8]) -> BuiltTgsReq {
    let body = &message.0.req_body;
    let client = principal_from_parts(&body.realm, body.cname.as_ref().expect("cname"));
    let service = principal_from_parts(&body.realm, body.sname.as_ref().expect("sname"));
    let kdc_realm = kerberos_string_to_string(&body.realm);
    let nonce = body.nonce;
    BuiltTgsReq {
        message,
        der: der.to_vec(),
        client,
        service,
        kdc_realm,
        nonce,
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

#[cfg(feature = "tokio")]
fn make_credential_current(credential: &mut ccache::Credential, now: u32) {
    credential.times.auth_time = now - 60;
    credential.times.start_time = now - 60;
    credential.times.end_time = now + 60 * 60;
    credential.times.renew_till = now + 2 * 60 * 60;
}

#[cfg(feature = "tokio")]
fn make_credential_expired(credential: &mut ccache::Credential, now: u32) {
    credential.times.auth_time = now - 2 * 60 * 60;
    credential.times.start_time = now - 2 * 60 * 60;
    credential.times.end_time = now - 60 * 60;
    credential.times.renew_till = 0;
}

#[cfg(feature = "tokio")]
fn config_without_kdcs() -> Config {
    Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {
 }
"#,
    )
    .expect("config parses")
}

#[cfg(feature = "tokio")]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

#[cfg(feature = "tokio")]
fn x_cacheconf_credential(client: &ccache::Principal) -> ccache::Credential {
    ccache::Credential {
        client: client.clone(),
        server: ccache::Principal::new(
            "X-CACHECONF:",
            0,
            vec!["krb5_ccache_conf_data".to_owned(), "fast_avail".to_owned()],
        ),
        key: ccache::EncryptionKey {
            etype: 0,
            value: Vec::new(),
        },
        times: ccache::CredentialTimes::default(),
        is_skey: false,
        ticket_flags: [0; 4],
        addresses: Vec::new(),
        auth_data: Vec::new(),
        ticket: b"yes".to_vec(),
        second_ticket: Vec::new(),
    }
}

#[cfg(feature = "tokio")]
fn matching_credentials<'a>(
    cache: &'a ccache::CCache,
    server: &ccache::Principal,
) -> Vec<&'a ccache::Credential> {
    cache
        .credentials()
        .iter()
        .filter(|credential| {
            credential.client.realm == "TEST.GOKRB5"
                && credential.client.components == ["testuser1"]
                && credential.server == *server
        })
        .collect()
}

#[cfg(feature = "tokio")]
fn temp_client_ccache_file(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-client-{name}-{}-{nanos}",
        std::process::id()
    ))
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
