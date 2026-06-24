use super::*;

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
fn as_req_options_from_libdefaults_sets_canonicalize_flag() {
    let defaults = rskrb5::config::LibDefaults {
        canonicalize: true,
        kdc_default_options: 0x0000_0010,
        ..Default::default()
    };
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::from_libdefaults(timestamp(1_893_553_447), 0x1122_3344, &defaults);

    let request = build_tgt_as_req(client, options).expect("AS-REQ builds");
    let decoded: rasn_kerberos::AsReq = rasn::der::decode(&request.der).expect("AS-REQ decodes");
    let body = &decoded.0.req_body;

    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        (KDC_OPTION_CANONICALIZE | 0x0000_0010)
            .to_be_bytes()
            .as_slice()
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
fn builds_pa_for_user_padata_with_s4u_checksum() {
    let user = Principal::new("ATHENA.MIT.EDU", 1, ["hftsai", "extra"]);
    let tgt_session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SESSION_KEY),
    };

    let padata = pa_for_user_padata(&user, &tgt_session_key).expect("PA-FOR-USER builds");

    assert_eq!(padata.r#type, PA_FOR_USER);
    let decoded =
        rskrb5::messages::PaForUser::decode_der(padata.value.as_ref()).expect("value decodes");
    assert_eq!(
        principal_from_parts(&decoded.user_realm, &decoded.user_name),
        user
    );
    assert_eq!(decoded.auth_package.as_bytes(), b"Kerberos");
    assert_eq!(decoded.cksum.r#type, -138);
    let s4u_bytes = s4u_byte_array(&user, "Kerberos");
    assert_eq!(
        hex_encode(&s4u_bytes),
        "010000006866747361696578747261415448454e412e4d49542e4544554b65726265726f73"
    );
    assert_eq!(
        decoded.cksum.checksum.as_ref(),
        kerb_checksum_hmac_md5(
            &tgt_session_key.value,
            &s4u_bytes,
            PA_FOR_USER_CHECKSUM_USAGE
        )
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
fn process_as_rep_validates_pa_req_enc_pa_rep_checksum() {
    let request = sample_request_with_pa_req_enc_pa_rep();
    let reply_key = reply_key();
    assert_eq!(
        u32::from_be_bytes(*TICKET_FLAGS) & TICKET_FLAG_ENC_PA_REP,
        TICKET_FLAG_ENC_PA_REP
    );
    let response = synthetic_as_rep_with_reply_key(
        &request,
        request.nonce,
        request.service.clone(),
        &reply_key,
    );

    let session = process_as_rep(&request, &response, &reply_key)
        .expect("AS-REP encrypted padata checksum validates");

    assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
    assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
}

#[test]
fn process_as_rep_rejects_invalid_pa_req_enc_pa_rep_checksum() {
    let request = sample_request_with_pa_req_enc_pa_rep();
    let reply_key = reply_key();
    let response = synthetic_as_rep_with_reply_key_and_encrypted_padata(
        &request,
        request.nonce,
        request.service.clone(),
        &reply_key,
        Some(fast_negotiation_encrypted_padata(
            &request, &reply_key, true,
        )),
    );

    let error = process_as_rep(&request, &response, &reply_key)
        .expect_err("invalid AS-REP encrypted padata checksum fails");

    assert!(matches!(error, Error::FastNegotiationChecksumMismatch));
}

#[test]
fn process_as_rep_requires_fast_marker_with_pa_req_enc_pa_rep_checksum() {
    let request = sample_request_with_pa_req_enc_pa_rep();
    let reply_key = reply_key();
    let response = synthetic_as_rep_with_reply_key_and_encrypted_padata(
        &request,
        request.nonce,
        request.service.clone(),
        &reply_key,
        Some(vec![pa_req_enc_pa_rep_padata(&request, &reply_key, false)]),
    );

    let error = process_as_rep(&request, &response, &reply_key)
        .expect_err("missing PA-FX-FAST marker fails");

    assert!(matches!(error, Error::InvalidFastNegotiationResponse));
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
