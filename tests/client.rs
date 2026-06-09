#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pretty_assertions::assert_eq;
#[cfg(feature = "tokio")]
use rskrb5::ccache;
use rskrb5::client::KpasswdRequestOptions;
use rskrb5::client::{
    AP_REP_ENCPART_USAGE, AP_REQ_AUTHENTICATOR_USAGE, AS_REP_ENCPART_USAGE,
    AS_REQ_PA_ENC_TIMESTAMP_USAGE, ApReqOptions, AsReqOptions, BuiltAsReq, BuiltTgsReq, Error,
    KDC_ERR_PREAUTH_REQUIRED, KDC_OPTION_RENEW, KDC_OPTION_RENEWABLE, KdcError, KdcTransport,
    PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_REQ_ENC_PA_REP, PA_TGS_REQ, PreauthKeyInfo, Principal,
    TGS_REP_ENCPART_SESSION_KEY_USAGE, TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
    TGS_REQ_AUTHENTICATOR_USAGE, TgsReqOptions, build_ap_req_with_confounder,
    build_kpasswd_request, build_kpasswd_request_with_confounders, build_preauthenticated_as_req,
    build_tgs_req_for_realm_with_confounder, build_tgs_req_with_confounder, build_tgt_as_req,
    build_tgt_renewal_req_with_confounder, build_ticket_renewal_req_with_confounder,
    default_password_salt, derive_password_reply_key, exchange_as_req, exchange_tgs_req,
    login_as_service_with_keytab, login_as_service_with_password, login_tgt_with_keytab,
    login_tgt_with_password, pa_enc_timestamp_with_confounder, process_as_rep, process_kdc_error,
    process_tgs_rep, process_tgs_rep_with_referral, renew_tgt, renew_ticket,
    select_preauth_key_info, verify_kpasswd_ap_rep,
};
#[cfg(feature = "tokio")]
use rskrb5::client::{KdcProtocol, PrunedSessions, TokioClient};
#[cfg(feature = "tokio")]
use rskrb5::config::Config;
use rskrb5::crypto::AesSha1Etype;
use rskrb5::kadmin::{
    ChangePasswdData, KPASSWD_SUCCESS, KRB_PRIV_ENCPART_USAGE, Reply as KpasswdReply,
    Request as KpasswdRequest, ipv4_host_address,
};
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;

mod common;

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
fn builds_preauthenticated_as_req_for_explicit_service() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let service = change_password_principal();
    let request = build_preauthenticated_as_req(
        client.clone(),
        service.clone(),
        AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_etypes(vec![18]),
        &reply_key(),
        Some(7),
    )
    .expect("AS-REQ builds");
    let decoded: rasn_kerberos::AsReq = rasn::der::decode(&request.der).expect("AS-REQ decodes");

    assert_eq!(request.client, client);
    assert_eq!(request.service, service);
    let body = &decoded.0.req_body;
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        change_password_principal()
    );
    let padata = decoded.0.padata.as_ref().expect("preauth padata");
    assert!(
        padata
            .iter()
            .any(|padata| padata.r#type == PA_ENC_TIMESTAMP)
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
fn builds_kpasswd_request_with_subkey_encrypted_payload() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let reply_key = EncryptionKey {
        etype: 18,
        value: vec![0x55; 32],
    };
    let change_data = ChangePasswdData::for_target(b"newpassword", 1, ["testuser1"], "TEST.GOKRB5")
        .expect("ChangePasswdData builds");

    let built = build_kpasswd_request_with_confounders(
        &service_ticket,
        &change_data,
        reply_key.clone(),
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
        &decode_hex(TGS_REQ_CONFOUNDER),
        &decode_hex(PREAUTH_CONFOUNDER),
    )
    .expect("kpasswd request builds");

    assert_eq!(built.reply_key, reply_key);
    assert_eq!(built.der, built.request.encode().expect("request encodes"));
    let parsed = KpasswdRequest::parse(&built.der).expect("request parses");
    assert_eq!(parsed.ap_req, built.request.ap_req);
    assert_eq!(parsed.krb_priv, built.request.krb_priv);

    let authenticator_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &service_ticket.session_key.value,
            parsed.ap_req.authenticator.cipher.as_ref(),
            AP_REQ_AUTHENTICATOR_USAGE,
        )
        .expect("AP-REQ authenticator decrypts");
    let authenticator: rasn_kerberos::Authenticator =
        rasn::der::decode(&authenticator_bytes).expect("Authenticator decodes");
    let subkey = authenticator.subkey.expect("authenticator subkey");
    assert_eq!(subkey.r#type, reply_key.etype);
    assert_eq!(subkey.value.as_ref(), reply_key.value.as_slice());
    assert_eq!(authenticator.seq_number, Some(42));

    let krb_priv_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &reply_key.value,
            parsed.krb_priv.enc_part.cipher.as_ref(),
            KRB_PRIV_ENCPART_USAGE,
        )
        .expect("KRB-PRIV decrypts");
    let enc_part: rasn_kerberos::EncKrbPrivPart =
        rasn::der::decode(&krb_priv_bytes).expect("EncKrbPrivPart decodes");
    let decoded_change_data =
        ChangePasswdData::decode_der(enc_part.user_data.as_ref()).expect("payload decodes");

    assert_eq!(decoded_change_data, change_data);
    assert_eq!(enc_part.seq_number, Some(42));
    assert_eq!(
        enc_part
            .usec
            .expect("KRB-PRIV usec")
            .to_string()
            .parse::<u32>()
            .expect("usec parses"),
        456_789
    );
    assert_eq!(
        system_time_from_kerberos_time(enc_part.timestamp.as_ref().expect("KRB-PRIV timestamp")),
        timestamp(1_893_553_452)
    );
}

#[test]
fn builds_kpasswd_request_with_generated_reply_key() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let change_data = ChangePasswdData::new(b"newpassword");

    let built = build_kpasswd_request(
        &service_ticket,
        &change_data,
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
    )
    .expect("kpasswd request builds");
    let parsed = KpasswdRequest::parse(&built.der).expect("request parses");

    assert_eq!(built.reply_key.etype, service_ticket.session_key.etype);
    assert_eq!(built.reply_key.value.len(), 32);

    let krb_priv_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &built.reply_key.value,
            parsed.krb_priv.enc_part.cipher.as_ref(),
            KRB_PRIV_ENCPART_USAGE,
        )
        .expect("KRB-PRIV decrypts");
    let enc_part: rasn_kerberos::EncKrbPrivPart =
        rasn::der::decode(&krb_priv_bytes).expect("EncKrbPrivPart decodes");
    let decoded_change_data =
        ChangePasswdData::decode_der(enc_part.user_data.as_ref()).expect("payload decodes");

    assert_eq!(decoded_change_data, change_data);
    assert_eq!(enc_part.seq_number, Some(42));
}

#[test]
fn verifies_kpasswd_reply_ap_rep_timestamp() {
    let built = sample_built_kpasswd_request();
    let ap_rep = kpasswd_ap_rep(&built, 456_789);
    let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep))
        .expect("kpasswd reply parses");

    let verified = verify_kpasswd_ap_rep(&reply, &built)
        .expect("AP-REP verifies")
        .expect("successful reply has AP-REP");

    assert_eq!(verified.ctime, timestamp(1_893_553_452));
    assert_eq!(verified.cusec, 456_789);
    assert_eq!(verified.sequence_number, Some(99));
}

#[test]
fn rejects_kpasswd_reply_ap_rep_timestamp_mismatch() {
    let built = sample_built_kpasswd_request();
    let ap_rep = kpasswd_ap_rep(&built, 456_790);
    let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep))
        .expect("kpasswd reply parses");

    assert!(matches!(
        verify_kpasswd_ap_rep(&reply, &built).expect_err("timestamp mismatch is rejected"),
        Error::KpasswdApRepTimestampMismatch { .. }
    ));
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
fn tokio_client_exposes_and_removes_cached_service_ticket() {
    let tgt = sample_tgt_session();
    let mut service_ticket = sample_service_ticket_session(&tgt);
    let now = SystemTime::now();
    service_ticket.start_time = now
        .checked_sub(Duration::from_secs(60))
        .expect("start time");
    service_ticket.end_time = now
        .checked_add(Duration::from_secs(60 * 60))
        .expect("end time");
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);
    client.cache_service_ticket(service_ticket.clone());

    let cached = client
        .cached_service_ticket(sample_service_principal())
        .expect("valid cached service ticket is returned");
    assert_eq!(cached.service, service_ticket.service);
    assert_eq!(cached.session_key, service_ticket.session_key);

    let removed = client
        .remove_cached_service_ticket(sample_service_principal())
        .expect("cached service ticket is removed");
    assert_eq!(removed.ticket, service_ticket.ticket);
    assert_eq!(client.cached_service_ticket_count(), 0);
    assert!(
        client
            .cached_service_ticket(sample_service_principal())
            .is_none()
    );
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_clears_service_ticket_cache_without_dropping_tgt() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket);

    assert_eq!(client.cached_service_ticket_count(), 1);
    client.clear_service_ticket_cache();

    assert_eq!(client.cached_service_ticket_count(), 0);
    assert_eq!(client.tgt_session().expect("TGT remains cached"), &tgt);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_cached_service_ticket_resolves_empty_realm_and_ignores_expired_entries() {
    let tgt = sample_tgt_session();
    let mut service_ticket = sample_service_ticket_session(&tgt);
    let now = SystemTime::now();
    service_ticket.start_time = now
        .checked_sub(Duration::from_secs(10 * 60))
        .expect("start time");
    service_ticket.end_time = now.checked_sub(Duration::from_secs(60)).expect("end time");

    let mut config = Config::new();
    config
        .domain_realm
        .insert("host.test.gokrb5".to_owned(), "TEST.GOKRB5".to_owned());
    let mut client = TokioClient::from_tgt_session(config, KdcProtocol::Tcp, tgt);
    client.cache_service_ticket(service_ticket);

    assert!(
        client
            .cached_service_ticket(Principal::new("", 2, ["HTTP", "host.test.gokrb5"]))
            .is_none()
    );
    assert_eq!(client.cached_service_ticket_count(), 1);
    assert!(
        client
            .remove_cached_service_ticket(Principal::new("", 2, ["HTTP", "host.test.gokrb5"]))
            .is_some()
    );
    assert_eq!(client.cached_service_ticket_count(), 0);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_prunes_unusable_sessions_but_keeps_renewable_entries() {
    let tgt = current_tgt_session(10, 50);
    let now = SystemTime::now();
    let expired_start = now
        .checked_sub(Duration::from_secs(2 * 60 * 60))
        .expect("expired start time");
    let expired_end = now
        .checked_sub(Duration::from_secs(60 * 60))
        .expect("expired end time");
    let future_renew_till = now
        .checked_add(Duration::from_secs(60 * 60))
        .expect("renew-till time");
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

    let mut expired_referral_tgt = sample_referral_tgt_session("EXPIRED.GOKRB5");
    expired_referral_tgt.auth_time = expired_start;
    expired_referral_tgt.start_time = expired_start;
    expired_referral_tgt.end_time = expired_end;
    expired_referral_tgt.renew_till = None;
    client
        .cache_tgt_session(expired_referral_tgt)
        .expect("expired referral TGT caches");

    let mut expired_service_ticket = sample_service_ticket_session(&tgt);
    expired_service_ticket.service =
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "expired.test.gokrb5"]);
    expired_service_ticket.start_time = expired_start;
    expired_service_ticket.end_time = expired_end;
    expired_service_ticket.renew_till = None;
    client.cache_service_ticket(expired_service_ticket);

    let mut renewable_service_ticket = sample_service_ticket_session(&tgt);
    renewable_service_ticket.service =
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "renewable.test.gokrb5"]);
    renewable_service_ticket.start_time = expired_start;
    renewable_service_ticket.end_time = expired_end;
    renewable_service_ticket.renew_till = Some(future_renew_till);
    client.cache_service_ticket(renewable_service_ticket.clone());

    let pruned = client.prune_unusable_sessions();

    assert_eq!(
        pruned,
        PrunedSessions {
            primary_tgt: false,
            tgt_sessions: 1,
            service_tickets: 1,
        }
    );
    assert!(!pruned.is_empty());
    assert_eq!(client.tgt_session_count(), 1);
    assert!(client.tgt_session().is_some());
    assert!(client.tgt_session_for_realm("EXPIRED.GOKRB5").is_none());
    assert_eq!(client.cached_service_ticket_count(), 1);
    assert!(
        client
            .cached_service_ticket(renewable_service_ticket.service.clone())
            .is_none()
    );
    assert!(
        client
            .remove_cached_service_ticket(renewable_service_ticket.service)
            .is_some()
    );
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_prunes_expired_nonrenewable_primary_tgt() {
    let mut tgt = current_tgt_session(70, 0);
    tgt.renew_till = None;
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);

    let pruned = client.prune_unusable_sessions();

    assert_eq!(
        pruned,
        PrunedSessions {
            primary_tgt: true,
            tgt_sessions: 1,
            service_tickets: 0,
        }
    );
    assert!(client.tgt_session().is_none());
    assert_eq!(client.tgt_session_count(), 0);
    assert!(client.prune_unusable_sessions().is_empty());
    assert!(PrunedSessions::default().is_empty());
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_destroy_clears_credentials_sessions_and_cache() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt)
        .with_password_credential(TESTUSER_PASSWORD);
    client.cache_service_ticket(service_ticket);

    client.destroy();

    assert!(client.tgt_session().is_none());
    assert_eq!(client.tgt_session_count(), 0);
    assert_eq!(client.cached_service_ticket_count(), 0);
    assert!(
        client
            .cached_service_ticket(sample_service_principal())
            .is_none()
    );
    let error = runtime()
        .block_on(client.login())
        .expect_err("destroyed client has no credentials or TGT");
    assert!(matches!(error, Error::NoClientCredentials));
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
fn tokio_client_affirm_login_returns_current_cache_only_tgt() {
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
        .block_on(client.affirm_login())
        .expect("current cache-only TGT is returned");

    assert_eq!(session.client, tgt.client);
    assert_eq!(session.service, tgt.service);
    assert_eq!(session.session_key, tgt.session_key);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_affirm_login_reuses_valid_tgt_with_attached_credentials() {
    let mut tgt = sample_tgt_session();
    let now = SystemTime::now();
    tgt.auth_time = now
        .checked_sub(Duration::from_secs(2 * 60))
        .expect("auth time");
    tgt.start_time = now
        .checked_sub(Duration::from_secs(60))
        .expect("start time");
    tgt.end_time = now
        .checked_add(Duration::from_secs(60 * 60))
        .expect("end time");
    tgt.renew_till = Some(
        now.checked_add(Duration::from_secs(2 * 60 * 60))
            .expect("renew time"),
    );
    let mut client = TokioClient::from_tgt_session(config_without_kdcs(), KdcProtocol::Tcp, tgt)
        .with_password_credential(TESTUSER_PASSWORD);

    let session = runtime()
        .block_on(client.affirm_login())
        .expect("valid TGT is reused without KDC endpoints");

    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
    assert_eq!(session.session_key.value, decode_hex(SESSION_KEY));
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
fn tokio_client_reports_tgt_refresh_due_window() {
    let missing = TokioClient::with_password(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
        TESTUSER_PASSWORD,
    );
    assert!(missing.tgt_refresh_due());

    let fresh =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, current_tgt_session(10, 50));
    assert!(!fresh.tgt_refresh_due());

    let due =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, current_tgt_session(55, 5));
    assert!(due.tgt_refresh_due());

    let expired =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, current_tgt_session(70, 0));
    assert!(expired.tgt_refresh_due());
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_refresh_tgt_if_needed_reuses_fresh_cache_only_tgt() {
    let tgt = current_tgt_session(10, 50);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

    let refreshed = runtime()
        .block_on(client.refresh_tgt_if_needed())
        .expect("fresh cache-only TGT is reused");

    assert_eq!(refreshed.session_key, tgt.session_key);
    assert_eq!(refreshed.ticket, tgt.ticket);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_auto_renewal_handle_aborts() {
    runtime().block_on(async {
        let client = std::sync::Arc::new(tokio::sync::Mutex::new(TokioClient::from_tgt_session(
            Config::new(),
            KdcProtocol::Tcp,
            current_tgt_session(10, 50),
        )));
        let renewal = TokioClient::spawn_auto_renewal_with_retry(client, Duration::from_millis(10));

        assert!(!renewal.is_finished());
        renewal.abort();
        tokio::task::yield_now().await;
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_validates_configuration() {
    let mut dns_config = Config::new();
    dns_config.libdefaults.dns_lookup_kdc = true;
    let configured = TokioClient::with_password(
        dns_config,
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
        TESTUSER_PASSWORD,
    );
    assert!(configured.is_configured());
    configured
        .validate_configuration()
        .expect("password-backed client with DNS KDC lookup is configured");

    let missing_name = TokioClient::with_password(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", ""),
        TESTUSER_PASSWORD,
    );
    assert!(!missing_name.is_configured());
    assert!(matches!(
        missing_name.validate_configuration(),
        Err(Error::MissingClientName)
    ));

    let missing_realm = TokioClient::with_password(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("", "testuser1"),
        TESTUSER_PASSWORD,
    );
    assert!(!missing_realm.is_configured());
    assert!(matches!(
        missing_realm.validate_configuration(),
        Err(Error::MissingClientRealm)
    ));

    let mut missing_credentials =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, sample_tgt_session());
    missing_credentials.destroy();
    assert!(!missing_credentials.is_configured());
    assert!(matches!(
        missing_credentials.validate_configuration(),
        Err(Error::NoClientCredentials)
    ));

    let missing_kdc = TokioClient::with_password(
        config_without_kdcs(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
        TESTUSER_PASSWORD,
    );
    assert!(!missing_kdc.is_configured());
    assert!(matches!(
        missing_kdc.validate_configuration(),
        Err(Error::NoConfiguredKdc { realm }) if realm == "TEST.GOKRB5"
    ));
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_diagnostics_reports_keytab_and_kdc_state() {
    let client = TokioClient::with_keytab(
        config_with_kdc(),
        KdcProtocol::Auto,
        Principal::user("TEST.GOKRB5", "testuser1"),
        keytab_with_reply_key(1),
    );

    let diagnostics = runtime().block_on(client.diagnostics());

    assert_eq!(diagnostics.client, "testuser1");
    assert_eq!(diagnostics.realm, "TEST.GOKRB5");
    assert_eq!(diagnostics.protocol, "Auto");
    assert_eq!(diagnostics.credential_source, "keytab");
    assert!(!diagnostics.has_tgt);
    assert_eq!(diagnostics.tgt_session_count, 0);
    assert_eq!(diagnostics.service_ticket_cache_count, 0);
    assert_eq!(diagnostics.default_tkt_enctypes, [18, 17]);
    assert_eq!(diagnostics.preferred_preauth_types, [18, 17]);
    assert_eq!(diagnostics.keytab_enctypes, [18]);
    assert_eq!(diagnostics.udp_kdcs, ["kdc.test.gokrb5:88"]);
    assert_eq!(diagnostics.tcp_kdcs, ["kdc.test.gokrb5:88"]);
    assert_eq!(
        diagnostics.errors,
        [
            "default_tkt_enctypes specifies 17 but this enctype is not available in the client's keytab",
            "preferred_preauth_types specifies 17 but this enctype is not available in the client's keytab",
        ]
    );
    assert!(!diagnostics.is_ok());

    let json = runtime()
        .block_on(client.diagnostics_json())
        .expect("diagnostics JSON renders");
    assert!(json.contains(r#""CredentialSource": "keytab""#));
    assert!(json.contains(r#""UDPKDCs": ["#));
    assert!(json.contains(r#""TCPKDCs": ["#));
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
fn tokio_client_renews_expired_renewable_cached_service_ticket() {
    runtime().block_on(async {
        let tgt = sample_tgt_session();
        let mut service_ticket = sample_service_ticket_session(&tgt);
        service_ticket.session_key.value = vec![0x44; 32];
        let cached_session_key = service_ticket.session_key.clone();
        let renewal_reply_key = service_ticket.session_key.clone();
        let now = SystemTime::now();
        service_ticket.start_time = now
            .checked_sub(Duration::from_secs(2 * 60 * 60))
            .expect("expired start time");
        service_ticket.end_time = now
            .checked_sub(Duration::from_secs(60 * 60))
            .expect("expired end time");
        service_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(60 * 60))
                .expect("renew-till time"),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            tgt,
        );
        client.cache_service_ticket(service_ticket.clone());
        assert_eq!(client.cached_service_ticket_count(), 1);

        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_kdc_request(&listener).await;
            let decoded: rasn_kerberos::TgsReq =
                rasn::der::decode(&request).expect("TGS-REQ decodes");
            let body = &decoded.0.req_body;
            let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;
            assert_eq!(
                body.kdc_options.0.as_raw_slice(),
                expected_options.to_be_bytes().as_slice()
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
                sample_service_principal()
            );

            let built = built_tgs_request_from_der(decoded, &request);
            let response = synthetic_tgs_rep(&built, built.nonce, &renewal_reply_key);
            write_tcp_kdc_response(&mut socket, &response).await;
        });

        let renewed = client
            .get_service_ticket(sample_service_principal())
            .await
            .expect("renewable cached service ticket renews");
        task.await.expect("KDC task succeeds");

        assert_eq!(renewed.service, sample_service_principal());
        assert_eq!(hex_encode(&renewed.session_key.value), SERVICE_SESSION_KEY);
        assert_eq!(client.cached_service_ticket_count(), 1);
        let cached = client
            .remove_cached_service_ticket(sample_service_principal())
            .expect("renewed service ticket is cached");
        assert_eq!(cached.session_key, renewed.session_key);
        assert_ne!(cached.session_key, cached_session_key);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_renews_ccache_loaded_renewable_service_ticket() {
    runtime().block_on(async {
        let tgt = sample_tgt_session();
        let mut service_ticket = sample_service_ticket_session(&tgt);
        service_ticket.session_key.value = vec![0x46; 32];
        let cached_session_key = service_ticket.session_key.clone();
        let renewal_reply_key = service_ticket.session_key.clone();
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
        service_credential.times.auth_time = now - 2 * 60 * 60;
        service_credential.times.start_time = now - 2 * 60 * 60;
        service_credential.times.end_time = now - 60 * 60;
        service_credential.times.renew_till = now + 60 * 60;
        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(service_credential);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_ccache(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            &cache,
        );
        assert_eq!(client.cached_service_ticket_count(), 1);

        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_kdc_request(&listener).await;
            let decoded: rasn_kerberos::TgsReq =
                rasn::der::decode(&request).expect("TGS-REQ decodes");
            let body = &decoded.0.req_body;
            let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;
            assert_eq!(
                body.kdc_options.0.as_raw_slice(),
                expected_options.to_be_bytes().as_slice()
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
                sample_service_principal()
            );

            let built = built_tgs_request_from_der(decoded, &request);
            let response = synthetic_tgs_rep(&built, built.nonce, &renewal_reply_key);
            write_tcp_kdc_response(&mut socket, &response).await;
        });

        let renewed = client
            .get_service_ticket(sample_service_principal())
            .await
            .expect("ccache-loaded renewable service ticket renews");
        task.await.expect("KDC task succeeds");

        assert_eq!(renewed.service, sample_service_principal());
        assert_eq!(hex_encode(&renewed.session_key.value), SERVICE_SESSION_KEY);
        let cached = client
            .remove_cached_service_ticket(sample_service_principal())
            .expect("renewed service ticket is cached");
        assert_eq!(cached.session_key, renewed.session_key);
        assert_ne!(cached.session_key, cached_session_key);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_renews_cached_referral_tgt_before_reusing_it() {
    runtime().block_on(async {
        let primary_tgt = current_tgt_session(10, 50);
        let mut referral_tgt = valid_referral_tgt_session(&primary_tgt, "RESDOM.GOKRB5");
        referral_tgt.session_key.value = vec![0x45; 32];
        let cached_referral_key = referral_tgt.session_key.clone();
        let referral_renewal_reply_key = referral_tgt.session_key.clone();
        let now = SystemTime::now();
        referral_tgt.start_time = now
            .checked_sub(Duration::from_secs(2 * 60 * 60))
            .expect("expired start time");
        referral_tgt.end_time = now
            .checked_sub(Duration::from_secs(60 * 60))
            .expect("expired end time");
        referral_tgt.renew_till = Some(
            now.checked_add(Duration::from_secs(60 * 60))
                .expect("renew-till time"),
        );

        let resource_service = Principal::new("RESDOM.GOKRB5", 2, ["HTTP", "app.resdom.gokrb5"]);
        let expected_client = primary_tgt.client.clone();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            primary_tgt,
        );
        client
            .cache_tgt_session(referral_tgt)
            .expect("expired referral TGT caches");

        let expected_resource_service = resource_service.clone();
        let task = tokio::spawn(async move {
            let (renewal_request, mut renewal_socket) = read_tcp_kdc_request(&listener).await;
            let renewal_decoded: rasn_kerberos::TgsReq =
                rasn::der::decode(&renewal_request).expect("renewal TGS-REQ decodes");
            let renewal_body = &renewal_decoded.0.req_body;
            let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;
            assert_eq!(
                renewal_body.kdc_options.0.as_raw_slice(),
                expected_options.to_be_bytes().as_slice()
            );
            assert_eq!(
                principal_from_parts(
                    &renewal_body.realm,
                    renewal_body.sname.as_ref().expect("renewal sname")
                ),
                Principal::tgt_service("RESDOM.GOKRB5")
            );
            let mut renewal_built = built_tgs_request_from_der(renewal_decoded, &renewal_request);
            renewal_built.client = expected_client.clone();
            let renewal_response = synthetic_tgs_rep(
                &renewal_built,
                renewal_built.nonce,
                &referral_renewal_reply_key,
            );
            write_tcp_kdc_response(&mut renewal_socket, &renewal_response).await;

            let (service_request, mut service_socket) = read_tcp_kdc_request(&listener).await;
            let service_decoded: rasn_kerberos::TgsReq =
                rasn::der::decode(&service_request).expect("service TGS-REQ decodes");
            let service_body = &service_decoded.0.req_body;
            assert_eq!(
                principal_from_parts(
                    &service_body.realm,
                    service_body.sname.as_ref().expect("service sname")
                ),
                expected_resource_service
            );
            let mut service_built = built_tgs_request_from_der(service_decoded, &service_request);
            service_built.client = expected_client;
            let renewed_referral_key = EncryptionKey {
                etype: 18,
                value: decode_hex(SERVICE_SESSION_KEY),
            };
            let service_response =
                synthetic_tgs_rep(&service_built, service_built.nonce, &renewed_referral_key);
            write_tcp_kdc_response(&mut service_socket, &service_response).await;
        });

        let ticket = client
            .get_service_ticket(resource_service.clone())
            .await
            .expect("service ticket is acquired through renewed referral TGT");
        task.await.expect("KDC task succeeds");

        assert_eq!(ticket.service, resource_service);
        assert_eq!(client.cached_service_ticket_count(), 1);
        let renewed_referral = client
            .tgt_session_for_realm("RESDOM.GOKRB5")
            .expect("renewed referral TGT is cached");
        assert_ne!(renewed_referral.session_key, cached_referral_key);
        assert_eq!(
            hex_encode(&renewed_referral.session_key.value),
            SERVICE_SESSION_KEY
        );
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_renews_tgt_session_for_realm() {
    runtime().block_on(async {
        let primary_tgt = current_tgt_session(10, 50);
        let mut referral_tgt = valid_referral_tgt_session(&primary_tgt, "RESDOM.GOKRB5");
        referral_tgt.session_key.value = vec![0x47; 32];
        let cached_referral_key = referral_tgt.session_key.clone();
        let referral_renewal_reply_key = referral_tgt.session_key.clone();
        let expected_client = primary_tgt.client.clone();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            primary_tgt,
        );
        client
            .cache_tgt_session(referral_tgt)
            .expect("referral TGT caches");

        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_kdc_request(&listener).await;
            let decoded: rasn_kerberos::TgsReq =
                rasn::der::decode(&request).expect("TGS-REQ decodes");
            let body = &decoded.0.req_body;
            let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;
            assert_eq!(
                body.kdc_options.0.as_raw_slice(),
                expected_options.to_be_bytes().as_slice()
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
                Principal::tgt_service("RESDOM.GOKRB5")
            );

            let mut built = built_tgs_request_from_der(decoded, &request);
            built.client = expected_client;
            let response = synthetic_tgs_rep(&built, built.nonce, &referral_renewal_reply_key);
            write_tcp_kdc_response(&mut socket, &response).await;
        });

        let renewed = client
            .renew_tgt_session_for_realm("RESDOM.GOKRB5")
            .await
            .expect("referral TGT renews explicitly");
        task.await.expect("KDC task succeeds");

        assert_eq!(renewed.service, Principal::tgt_service("RESDOM.GOKRB5"));
        assert_ne!(renewed.session_key, cached_referral_key);
        assert_eq!(hex_encode(&renewed.session_key.value), SERVICE_SESSION_KEY);
        assert_eq!(
            client
                .tgt_session_for_realm("RESDOM.GOKRB5")
                .expect("renewed referral is cached")
                .session_key,
            renewed.session_key
        );
        assert!(matches!(
            client
                .renew_tgt_session_for_realm("MISSING.GOKRB5")
                .await
                .expect_err("missing realm has no TGT"),
            Error::NoTgtSession
        ));
    });
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

    let name_path = temp_client_ccache_file("export-save-name");
    let name = format!("FILE:{}", name_path.display());
    client
        .save_ccache_name(&name)
        .expect("client saves ccache by name");
    let loaded_by_name = ccache::CCache::load_name(&name).expect("named ccache loads");
    let _ = std::fs::remove_file(&name_path);
    assert_eq!(loaded_by_name, cache);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_loads_from_ccache_name() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket);
    let cache = client.to_ccache().expect("client exports ccache");
    let path = temp_client_ccache_file("load-name");
    let name = format!("FILE:{}", path.display());
    cache.save_name(&name).expect("ccache saves by name");

    let loaded = TokioClient::from_ccache_name(Config::new(), KdcProtocol::Tcp, &name)
        .expect("client loads ccache by name");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_loads_from_ccache_env() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket);
    let cache = client.to_ccache().expect("client exports ccache");
    let path = temp_client_ccache_file("load-env");
    let name = format!("FILE:{}", path.display());
    let _env = common::EnvVarGuard::set_krb5ccname(&name);
    cache.save_name(&name).expect("ccache saves by name");

    let loaded = TokioClient::from_ccache_env(Config::new(), KdcProtocol::Tcp)
        .expect("client loads ccache from env");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_saves_and_loads_dir_collection_ccache_name() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
    client.cache_service_ticket(service_ticket);
    let directory = temp_client_ccache_dir("dir-collection-name");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    let name = format!("DIR:{}", directory.display());

    client
        .save_ccache_name(&name)
        .expect("client saves ccache to DIR collection");
    let loaded = TokioClient::from_ccache_name(Config::new(), KdcProtocol::Tcp, &name)
        .expect("client loads ccache from DIR collection");

    let _ = std::fs::remove_file(directory.join("tkt"));
    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_loads_from_config_default_ccache_name() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let directory = temp_client_ccache_dir("default-ccache-name");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    let name = format!("DIR:{}", directory.display());
    let mut client = TokioClient::from_tgt_session(
        config_with_default_ccache_name(name.clone()),
        KdcProtocol::Tcp,
        tgt.clone(),
    );
    client.cache_service_ticket(service_ticket);
    client
        .save_default_ccache_name()
        .expect("client saves configured ccache");

    let loaded = TokioClient::from_default_ccache_name(
        config_with_default_ccache_name(name),
        KdcProtocol::Tcp,
    )
    .expect("client loads configured default ccache");

    let _ = std::fs::remove_file(directory.join("tkt"));
    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_uses_config_default_ccache_when_env_is_absent() {
    let _env = common::EnvVarGuard::remove_krb5ccname();

    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let directory = temp_client_ccache_dir("default-ccache-env-fallback");
    std::fs::create_dir(&directory).expect("temp DIR collection is created");
    let name = format!("DIR:{}", directory.display());
    let mut client = TokioClient::from_tgt_session(
        config_with_default_ccache_name(name.clone()),
        KdcProtocol::Tcp,
        tgt.clone(),
    );
    client.cache_service_ticket(service_ticket);
    client
        .save_default_ccache()
        .expect("client saves default ccache");

    let loaded =
        TokioClient::from_default_ccache(config_with_default_ccache_name(name), KdcProtocol::Tcp)
            .expect("client loads default ccache");
    loaded
        .update_default_ccache()
        .expect("client updates default ccache");

    let _ = std::fs::remove_file(directory.join("tkt"));
    let _ = std::fs::remove_file(directory.join("primary"));
    let _ = std::fs::remove_dir(&directory);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_prefers_env_default_ccache_over_config_name() {
    let tgt = sample_tgt_session();
    let service_ticket = sample_service_ticket_session(&tgt);
    let path = temp_client_ccache_file("default-ccache-env-precedence");
    let env_name = format!("FILE:{}", path.display());
    let _env = common::EnvVarGuard::set_krb5ccname(&env_name);
    let config_default = "MEMORY:config-default".to_owned();
    let mut client = TokioClient::from_tgt_session(
        config_with_default_ccache_name(config_default.clone()),
        KdcProtocol::Tcp,
        tgt.clone(),
    );
    client.cache_service_ticket(service_ticket);
    client
        .save_default_ccache()
        .expect("client saves default ccache from env");

    let loaded = TokioClient::from_default_ccache(
        config_with_default_ccache_name(config_default),
        KdcProtocol::Tcp,
    )
    .expect("client loads default ccache from env");
    loaded
        .update_default_ccache()
        .expect("client updates default ccache from env");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.tgt_session().expect("TGT reloads"), &tgt);
    assert_eq!(loaded.cached_service_ticket_count(), 1);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_rejects_missing_config_default_ccache_name() {
    let error = TokioClient::from_default_ccache_name(Config::new(), KdcProtocol::Tcp)
        .expect_err("missing default ccache name is rejected");

    assert!(matches!(error, Error::NoDefaultCCacheName));

    let client =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, sample_tgt_session());
    let error = client
        .save_default_ccache_name()
        .expect_err("missing default ccache name is rejected");
    assert!(matches!(error, Error::NoDefaultCCacheName));

    let error = client
        .update_default_ccache_name()
        .expect_err("missing default ccache name is rejected");
    assert!(matches!(error, Error::NoDefaultCCacheName));

    let _env = common::EnvVarGuard::remove_krb5ccname();

    let error = TokioClient::from_default_ccache(Config::new(), KdcProtocol::Tcp)
        .expect_err("missing default ccache name is rejected");
    assert!(matches!(error, Error::NoDefaultCCacheName));

    let error = client
        .save_default_ccache()
        .expect_err("missing default ccache name is rejected");
    assert!(matches!(error, Error::NoDefaultCCacheName));

    let error = client
        .update_default_ccache()
        .expect_err("missing default ccache name is rejected");
    assert!(matches!(error, Error::NoDefaultCCacheName));
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_loads_client_keytab_from_config_name() {
    let keytab = keytab_with_reply_key(1);
    let path = temp_client_keytab_file("load-config-name");
    let name = format!("FILE:{}", path.display());
    keytab.save_name(&name).expect("keytab saves by name");

    let client = TokioClient::with_client_keytab_from_config(
        config_with_client_keytab_name(name),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect("client loads keytab by config name");
    let _ = std::fs::remove_file(&path);

    let diagnostics = runtime().block_on(client.diagnostics());
    assert_eq!(diagnostics.credential_source, "keytab");
    assert_eq!(diagnostics.keytab_enctypes, [18]);
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_loads_keytab_from_env() {
    let keytab = keytab_with_reply_key(1);
    let path = temp_client_keytab_file("load-keytab-env");
    let name = format!("FILE:{}", path.display());
    keytab.save_name(&name).expect("keytab saves by name");
    let _env = common::EnvVarGuard::set_krb5_ktname(&name);

    let client = TokioClient::with_keytab_from_env(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect("client loads keytab from env");
    let _ = std::fs::remove_file(&path);

    let diagnostics = runtime().block_on(client.diagnostics());
    assert_eq!(diagnostics.credential_source, "keytab");
    assert_eq!(diagnostics.keytab_enctypes, [18]);
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_loads_client_keytab_from_env() {
    let keytab = keytab_with_reply_key(1);
    let path = temp_client_keytab_file("load-client-keytab-env");
    let name = format!("FILE:{}", path.display());
    keytab.save_name(&name).expect("keytab saves by name");
    let _env = common::EnvVarGuard::set_krb5_client_ktname(&name);

    let client = TokioClient::with_client_keytab_from_env(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect("client loads client keytab from env");
    let _ = std::fs::remove_file(&path);

    let diagnostics = runtime().block_on(client.diagnostics());
    assert_eq!(diagnostics.credential_source, "keytab");
    assert_eq!(diagnostics.keytab_enctypes, [18]);
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_loads_default_client_keytab_when_env_is_absent() {
    let _env = common::EnvVarGuard::remove_krb5_client_ktname();

    let keytab = keytab_with_reply_key(1);
    let path = temp_client_keytab_file("load-default-client-keytab");
    let name = format!("FILE:{}", path.display());
    keytab.save_name(&name).expect("keytab saves by name");

    let client = TokioClient::with_client_keytab_from_default(
        config_with_client_keytab_name(name),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect("client loads default client keytab");
    let _ = std::fs::remove_file(&path);

    let diagnostics = runtime().block_on(client.diagnostics());
    assert_eq!(diagnostics.credential_source, "keytab");
    assert_eq!(diagnostics.keytab_enctypes, [18]);
}

#[cfg(all(feature = "tokio", feature = "serde"))]
#[test]
fn tokio_client_prefers_env_client_keytab_over_config_name() {
    let keytab = keytab_with_reply_key(1);
    let path = temp_client_keytab_file("load-env-client-keytab");
    let env_name = format!("FILE:{}", path.display());
    keytab.save_name(&env_name).expect("keytab saves by name");
    let _env = common::EnvVarGuard::set_krb5_client_ktname(&env_name);
    let missing_config_name = format!(
        "FILE:{}",
        temp_client_keytab_file("missing-config-client-keytab").display()
    );

    let client = TokioClient::with_client_keytab_from_default(
        config_with_client_keytab_name(missing_config_name),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect("client loads env client keytab before config default");
    let _ = std::fs::remove_file(&path);

    let diagnostics = runtime().block_on(client.diagnostics());
    assert_eq!(diagnostics.credential_source, "keytab");
    assert_eq!(diagnostics.keytab_enctypes, [18]);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_reports_missing_client_keytab_env() {
    let _env = common::EnvVarGuard::remove_krb5_client_ktname();

    let error = TokioClient::with_client_keytab_from_env(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
    )
    .expect_err("missing client keytab env is rejected");

    assert!(matches!(error, Error::DefaultClientKeytabName(_)));
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_tracks_multiple_tgt_sessions() {
    let primary_tgt = sample_tgt_session();
    let referral_tgt = sample_referral_tgt_session("RESDOM.GOKRB5");
    let mut client =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, primary_tgt.clone());

    client
        .cache_tgt_session(referral_tgt.clone())
        .expect("referral TGT caches");

    assert_eq!(client.tgt_session_count(), 2);
    assert_eq!(
        client
            .tgt_session_for_realm("TEST.GOKRB5")
            .expect("primary TGT is cached")
            .service,
        primary_tgt.service
    );
    assert_eq!(
        client
            .tgt_session_for_realm("RESDOM.GOKRB5")
            .expect("referral TGT is cached")
            .service,
        referral_tgt.service
    );

    let cache = client.to_ccache().expect("client exports ccache");
    assert_eq!(cache.entries().len(), 2);
    assert!(cache.contains_server(&["krbtgt", "TEST.GOKRB5"]));
    assert!(cache.contains_server(&["krbtgt", "RESDOM.GOKRB5"]));

    let reloaded = TokioClient::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
    assert_eq!(reloaded.tgt_session_count(), 2);
    assert!(reloaded.tgt_session_for_realm("RESDOM.GOKRB5").is_some());

    let removed_referral = client
        .remove_tgt_session_for_realm("RESDOM.GOKRB5")
        .expect("referral TGT is removed");
    assert_eq!(removed_referral.service, referral_tgt.service);
    assert_eq!(client.tgt_session_count(), 1);
    assert!(client.tgt_session_for_realm("RESDOM.GOKRB5").is_none());
    assert_eq!(
        client.tgt_session().expect("primary TGT remains").service,
        primary_tgt.service
    );

    let removed_primary = client
        .remove_tgt_session_for_realm("TEST.GOKRB5")
        .expect("primary TGT is removed");
    assert_eq!(removed_primary.service, primary_tgt.service);
    assert!(client.tgt_session().is_none());
    assert_eq!(client.tgt_session_count(), 0);
    assert!(
        client
            .remove_tgt_session_for_realm("MISSING.GOKRB5")
            .is_none()
    );
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
    let name = format!("FILE:{}", path.display());
    client
        .update_ccache_name(&name)
        .expect("client updates ccache name");
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

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_changes_password_with_cached_changepw_ticket() {
    runtime().block_on(async {
        let tgt = sample_tgt_session();
        let changepw = change_password_principal();
        let request = build_tgs_req_with_confounder(
            &tgt,
            changepw,
            TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
            timestamp(1_893_553_451),
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER),
        )
        .expect("changepw TGS-REQ builds");
        let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
        let mut changepw_ticket =
            process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
        let now = SystemTime::now();
        changepw_ticket.start_time = now
            .checked_sub(Duration::from_secs(60))
            .expect("start time");
        changepw_ticket.end_time = now
            .checked_add(Duration::from_secs(60 * 60))
            .expect("end time");
        changepw_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(2 * 60 * 60))
                .expect("renew time"),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local kpasswd listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kpasswd_server(addr.to_string()),
            KdcProtocol::Tcp,
            tgt,
        );
        client.cache_service_ticket(changepw_ticket);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .await
                .expect("read request length");
            let request_len = u32::from_be_bytes(header) as usize;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).await.expect("read request");
            let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
            assert_eq!(parsed.ap_req.msg_type, rasn::types::Integer::from(14));
            assert_eq!(parsed.krb_priv.msg_type, rasn::types::Integer::from(21));

            let response = kpasswd_reply_frame(
                0,
                &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed"),
            );
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write response length");
            socket.write_all(&response).await.expect("write response");
        });

        let result = client
            .change_password_with_options(
                b"newpassword",
                KpasswdRequestOptions::new(
                    timestamp(1_893_553_452),
                    456_789,
                    42,
                    ipv4_host_address([127, 0, 0, 1]),
                ),
            )
            .await
            .expect("change password succeeds");

        task.await.expect("kpasswd listener task completes");
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
    });
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
fn login_as_service_with_password_retries_for_explicit_service() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let service = change_password_principal();
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_etypes(vec![18]);
    let key_info = password_key_info();
    let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
        .expect("password key derives");
    let mut transport = PreauthTransport::new(reply_key, None);

    let session = login_as_service_with_password(
        &mut transport,
        client.clone(),
        service.clone(),
        TESTUSER_PASSWORD,
        options,
    )
    .expect("password login succeeds");

    assert_eq!(transport.calls, 2);
    assert_eq!(session.client, client);
    assert_eq!(session.service, service);
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
fn login_as_service_with_keytab_retries_for_explicit_service() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let service = change_password_principal();
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_etypes(vec![18]);
    let keytab = keytab_with_reply_key(7);
    let mut transport = PreauthTransport::new(reply_key(), Some(7));

    let session = login_as_service_with_keytab(
        &mut transport,
        client.clone(),
        service.clone(),
        &keytab,
        options,
    )
    .expect("keytab login succeeds");

    assert_eq!(transport.calls, 2);
    assert_eq!(session.client, client);
    assert_eq!(session.service, service);
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

fn sample_referral_tgt_session(realm: &str) -> rskrb5::client::AsRepSession {
    let mut tgt = sample_tgt_session();
    tgt.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt".to_owned(), realm.to_owned()]);
    tgt.session_key.value = vec![0x9a; 32];
    tgt.ticket = format!("referral-ticket-{realm}").into_bytes();
    tgt
}

#[cfg(feature = "tokio")]
fn valid_referral_tgt_session(
    tgt: &rskrb5::client::AsRepSession,
    realm: &str,
) -> rskrb5::client::AsRepSession {
    let referral_service = Principal::tgt_service(realm);
    let request = build_tgs_req_with_confounder(
        tgt,
        referral_service.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x8877_6655).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("referral TGS-REQ builds");
    let response =
        synthetic_tgs_rep_with_service(&request, request.nonce, &tgt.session_key, referral_service);
    process_tgs_rep_with_referral(&request, &response, &tgt.session_key)
        .expect("referral TGT validates")
}

#[cfg(feature = "tokio")]
fn current_tgt_session(
    auth_age_minutes: u64,
    remaining_minutes: u64,
) -> rskrb5::client::AsRepSession {
    let now = SystemTime::now();
    let mut tgt = sample_tgt_session();
    tgt.auth_time = now
        .checked_sub(Duration::from_secs(auth_age_minutes * 60))
        .expect("auth time");
    tgt.start_time = tgt.auth_time;
    tgt.end_time = if remaining_minutes == 0 {
        now.checked_sub(Duration::from_secs(60))
            .expect("expired end time")
    } else {
        now.checked_add(Duration::from_secs(remaining_minutes * 60))
            .expect("end time")
    };
    tgt.renew_till = Some(
        now.checked_add(Duration::from_secs(24 * 60 * 60))
            .expect("renew time"),
    );
    tgt.key_expiration = Some(tgt.end_time);
    tgt
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

fn sample_built_kpasswd_request() -> rskrb5::client::BuiltKpasswdRequest {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let reply_key = EncryptionKey {
        etype: 18,
        value: vec![0x55; 32],
    };
    let change_data = ChangePasswdData::for_target(b"newpassword", 1, ["testuser1"], "TEST.GOKRB5")
        .expect("ChangePasswdData builds");

    build_kpasswd_request_with_confounders(
        &service_ticket,
        &change_data,
        reply_key,
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
        &decode_hex(TGS_REQ_CONFOUNDER),
        &decode_hex(PREAUTH_CONFOUNDER),
    )
    .expect("kpasswd request builds")
}

fn kpasswd_ap_rep(built: &rskrb5::client::BuiltKpasswdRequest, cusec: u32) -> Vec<u8> {
    let enc_part = rasn_kerberos::EncApRepPart {
        ctime: kerberos_time(1_893_553_452),
        cusec: rasn::types::Integer::from(cusec),
        subkey: None,
        seq_number: Some(99),
    };
    let plaintext = rasn::der::encode(&enc_part).expect("EncApRepPart encodes");
    let cipher = AesSha1Etype::Aes256
        .encrypt_message_with_confounder(
            &built.reply_key.value,
            &plaintext,
            AP_REP_ENCPART_USAGE,
            &decode_hex(AS_REP_CONFOUNDER),
        )
        .expect("AP-REP encrypts");
    let ap_rep = rasn_kerberos::ApRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(15),
        enc_part: rasn_kerberos::EncryptedData {
            etype: built.reply_key.etype,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    rasn::der::encode(&ap_rep).expect("AP-REP encodes")
}

fn kpasswd_reply_with_ap_rep(
    built: &rskrb5::client::BuiltKpasswdRequest,
    ap_rep: &[u8],
) -> Vec<u8> {
    let mut body = ap_rep.to_vec();
    body.extend_from_slice(&rasn::der::encode(&built.request.krb_priv).expect("KRB-PRIV encodes"));
    kpasswd_reply_frame(ap_rep.len() as u16, &body)
}

fn sample_service_principal() -> Principal {
    Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
}

fn change_password_principal() -> Principal {
    Principal::new("TEST.GOKRB5", 1, ["kadmin", "changepw"])
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
fn config_with_kdc() -> Config {
    Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 preferred_preauth_types = 18 17

[realms]
 TEST.GOKRB5 = {
  kdc = kdc.test.gokrb5
 }
"#,
    )
    .expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_kdc_server(server: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {{
  kdc = {server}
 }}
 RESDOM.GOKRB5 = {{
  kdc = {server}
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_client_keytab_name(keytab_name: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_client_keytab_name = {keytab_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_default_ccache_name(cache_name: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_ccache_name = {cache_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_kpasswd_server(server: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 TEST.GOKRB5 = {{
  kpasswd_server = {server}
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
async fn read_tcp_kdc_request(listener: &TcpListener) -> (Vec<u8>, tokio::net::TcpStream) {
    let (mut socket, _) = listener.accept().await.expect("accept client");
    let mut header = [0; 4];
    socket
        .read_exact(&mut header)
        .await
        .expect("read request length");
    let request_len = u32::from_be_bytes(header) as usize;
    let mut request = vec![0; request_len];
    socket.read_exact(&mut request).await.expect("read request");
    (request, socket)
}

#[cfg(feature = "tokio")]
async fn write_tcp_kdc_response(socket: &mut tokio::net::TcpStream, response: &[u8]) {
    socket
        .write_all(&(response.len() as u32).to_be_bytes())
        .await
        .expect("write response length");
    socket.write_all(response).await.expect("write response");
}

#[cfg(feature = "tokio")]
fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Vec<u8> {
    let message_length = 6 + body.len();
    assert!(u16::try_from(message_length).is_ok());

    let mut frame = Vec::with_capacity(message_length);
    frame.extend_from_slice(&(message_length as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&ap_rep_length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

#[cfg(feature = "tokio")]
fn kpasswd_result_krb_error(code: u16, text: &str) -> Vec<u8> {
    let mut e_data = Vec::with_capacity(2 + text.len());
    e_data.extend_from_slice(&code.to_be_bytes());
    e_data.extend_from_slice(text.as_bytes());

    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: 52,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&change_password_principal()),
        e_text: Some(kerberos_string(text)),
        e_data: Some(e_data.into()),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
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

#[cfg(feature = "tokio")]
fn temp_client_ccache_dir(name: &str) -> std::path::PathBuf {
    temp_client_ccache_file(name)
}

#[cfg(feature = "tokio")]
fn temp_client_keytab_file(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-client-keytab-{name}-{}-{nanos}",
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
