use super::*;

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
fn tgs_req_options_from_libdefaults_sets_canonicalize_flag() {
    let defaults = rskrb5::config::LibDefaults {
        canonicalize: true,
        kdc_default_options: 0x0000_0010,
        ..Default::default()
    };
    let tgt = sample_tgt_session();
    let service = sample_service_principal();
    let options = TgsReqOptions::from_libdefaults(timestamp(1_893_553_450), 0x5566_7788, &defaults);

    let request = build_tgs_req_with_confounder(
        &tgt,
        service,
        options,
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");
    let body = &decoded.0.req_body;

    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        (KDC_OPTION_CANONICALIZE | 0x0000_0010)
            .to_be_bytes()
            .as_slice()
    );
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
fn builds_s4u2self_tgs_req_with_pa_for_user() {
    let mut service_tgt = sample_tgt_session();
    service_tgt.client = sample_service_principal();
    let user = Principal::user("TEST.GOKRB5", "delegated-user");

    let request = build_s4u2self_req_with_confounder(
        &service_tgt,
        user.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x5566_7788).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("S4U2Self TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");

    assert_eq!(request.client, user);
    assert_eq!(request.service, service_tgt.client);
    assert_eq!(request.kdc_realm, "TEST.GOKRB5");
    assert_eq!(
        principal_from_parts(
            &decoded.0.req_body.realm,
            decoded.0.req_body.cname.as_ref().expect("cname")
        ),
        service_tgt.client
    );
    assert_eq!(
        principal_from_parts(
            &decoded.0.req_body.realm,
            decoded.0.req_body.sname.as_ref().expect("sname")
        ),
        service_tgt.client
    );

    let padata = decoded.0.padata.as_ref().expect("S4U TGS-REQ padata");
    assert_eq!(padata.len(), 2);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
    assert_eq!(padata[1].r#type, PA_FOR_USER);
    let pa_for_user = rskrb5::messages::PaForUser::decode_der(padata[1].value.as_ref())
        .expect("PA-FOR-USER decodes");
    assert_eq!(
        principal_from_parts(&pa_for_user.user_realm, &pa_for_user.user_name),
        user
    );
    assert_eq!(pa_for_user.auth_package.as_bytes(), b"Kerberos");
    assert_eq!(pa_for_user.cksum.r#type, -138);
    let s4u_bytes = s4u_byte_array(&user, "Kerberos");
    let expected_checksum = kerb_checksum_hmac_md5(
        &service_tgt.session_key.value,
        &s4u_bytes,
        PA_FOR_USER_CHECKSUM_USAGE,
    );
    assert_eq!(pa_for_user.cksum.checksum.as_ref(), expected_checksum);
}

#[test]
fn builds_s4u2proxy_tgs_req_with_evidence_ticket() {
    let user_tgt = sample_tgt_session();
    let evidence_ticket = sample_service_ticket_session(&user_tgt);
    let mut service_tgt = sample_tgt_session();
    service_tgt.client = sample_service_principal();
    let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);

    let request = build_s4u2proxy_req_with_confounder(
        &service_tgt,
        &evidence_ticket,
        target_service.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x9988_7766).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("S4U2Proxy TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");
    let body = &decoded.0.req_body;

    assert_eq!(request.client, evidence_ticket.client);
    assert_eq!(request.service, target_service);
    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
        service_tgt.client
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        target_service
    );
    let additional_tickets = body
        .additional_tickets
        .as_ref()
        .expect("S4U2Proxy additional ticket");
    assert_eq!(additional_tickets.len(), 1);
    assert_eq!(
        principal_from_parts(&additional_tickets[0].realm, &additional_tickets[0].sname),
        service_tgt.client
    );
    let padata = decoded.0.padata.as_ref().expect("S4U2Proxy padata");
    assert_eq!(padata.len(), 1);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
}

#[test]
fn builds_s4u2proxy_tgs_req_with_pac_options() {
    let user_tgt = sample_tgt_session();
    let evidence_ticket = sample_service_ticket_session(&user_tgt);
    let mut service_tgt = sample_tgt_session();
    service_tgt.client = sample_service_principal();
    let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
    let pac_options = pa_pac_options_padata(PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION)
        .expect("PA-PAC-OPTIONS padata builds");

    let request = build_s4u2proxy_req_with_confounder(
        &service_tgt,
        &evidence_ticket,
        target_service,
        TgsReqOptions::new(timestamp(1_893_553_450), 0x8877_6655)
            .with_etypes(vec![18])
            .with_padata(vec![pac_options]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("S4U2Proxy TGS-REQ builds");
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request.der).expect("TGS-REQ decodes");
    let padata = decoded.0.padata.as_ref().expect("S4U2Proxy padata");

    assert_eq!(padata.len(), 2);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
    assert_eq!(padata[1].r#type, PA_PAC_OPTIONS);
    let pac_options = rskrb5::messages::PaPacOptions::decode_der(padata[1].value.as_ref())
        .expect("PA-PAC-OPTIONS decodes");
    assert_eq!(
        pac_options.bits(),
        PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION
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
fn s4u2self_uses_transport_boundary() {
    let mut service_tgt = sample_tgt_session();
    service_tgt.client = sample_service_principal();
    let user = Principal::user("TEST.GOKRB5", "delegated-user");
    let mut transport = S4uTransport {
        session_key: service_tgt.session_key.clone(),
        expected_service: service_tgt.client.clone(),
        expected_user: user.clone(),
        calls: 0,
    };

    let session = s4u2self(
        &mut transport,
        &service_tgt,
        user.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x6677_8899).with_etypes(vec![18]),
    )
    .expect("S4U2Self exchange succeeds");

    assert_eq!(transport.calls, 1);
    assert_eq!(session.client, user);
    assert_eq!(session.service, service_tgt.client);
}

#[test]
fn s4u2proxy_uses_transport_boundary() {
    let user_tgt = sample_tgt_session();
    let evidence_ticket = sample_service_ticket_session(&user_tgt);
    let mut service_tgt = sample_tgt_session();
    service_tgt.client = sample_service_principal();
    let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
    let mut transport = S4u2ProxyTransport {
        session_key: service_tgt.session_key.clone(),
        expected_frontend_service: service_tgt.client.clone(),
        expected_target_service: target_service.clone(),
        expected_client: evidence_ticket.client.clone(),
        calls: 0,
    };

    let session = s4u2proxy(
        &mut transport,
        &service_tgt,
        &evidence_ticket,
        target_service.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x6655_4433).with_etypes(vec![18]),
    )
    .expect("S4U2Proxy exchange succeeds");

    assert_eq!(transport.calls, 1);
    assert_eq!(session.client, evidence_ticket.client);
    assert_eq!(session.service, target_service);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_transport_s4u2self_uses_tcp_kdc() {
    runtime().block_on(async {
        let mut service_tgt = current_tgt_session(5, 180);
        service_tgt.client = sample_service_principal();
        let user = Principal::user("TEST.GOKRB5", "delegated-user");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");

        let task = tokio::spawn(serve_s4u2self_tcp_request(
            listener,
            service_tgt.session_key.clone(),
            service_tgt.client.clone(),
            user.clone(),
        ));

        let session = TokioKdcTransport::new()
            .s4u2self(
                KdcProtocol::Tcp,
                addr,
                &service_tgt,
                user.clone(),
                TgsReqOptions::new(timestamp(1_893_553_450), 0x6677_8899).with_etypes(vec![18]),
            )
            .await
            .expect("Tokio transport S4U2Self succeeds");
        task.await.expect("KDC task succeeds");

        assert_eq!(session.client, user);
        assert_eq!(session.service, service_tgt.client);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_s4u2self_uses_current_service_tgt_without_service_cache() {
    runtime().block_on(async {
        let mut service_tgt = current_tgt_session(5, 180);
        service_tgt.client = sample_service_principal();
        let user = Principal::user("TEST.GOKRB5", "delegated-user");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            service_tgt.clone(),
        );

        let task = tokio::spawn(serve_s4u2self_tcp_request(
            listener,
            service_tgt.session_key.clone(),
            service_tgt.client.clone(),
            user.clone(),
        ));

        let session = client
            .s4u2self_with_options(
                user.clone(),
                TgsReqOptions::new(timestamp(1_893_553_450), 0x7766_5544).with_etypes(vec![18]),
            )
            .await
            .expect("Tokio client S4U2Self succeeds");
        task.await.expect("KDC task succeeds");

        assert_eq!(session.client, user);
        assert_eq!(session.service, service_tgt.client);
        assert_eq!(client.cached_service_ticket_count(), 0);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_transport_s4u2proxy_uses_tcp_kdc() {
    runtime().block_on(async {
        let user_tgt = sample_tgt_session();
        let evidence_ticket = sample_service_ticket_session(&user_tgt);
        let mut service_tgt = current_tgt_session(5, 180);
        service_tgt.client = sample_service_principal();
        let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");

        let task = tokio::spawn(serve_s4u2proxy_tcp_request(
            listener,
            service_tgt.session_key.clone(),
            service_tgt.client.clone(),
            target_service.clone(),
            evidence_ticket.client.clone(),
        ));

        let session = TokioKdcTransport::new()
            .s4u2proxy(
                KdcProtocol::Tcp,
                addr,
                &service_tgt,
                &evidence_ticket,
                target_service.clone(),
                TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
            )
            .await
            .expect("Tokio transport S4U2Proxy succeeds");
        task.await.expect("KDC task succeeds");

        assert_eq!(session.client, evidence_ticket.client);
        assert_eq!(session.service, target_service);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_s4u2proxy_uses_current_service_tgt_without_service_cache() {
    runtime().block_on(async {
        let user_tgt = sample_tgt_session();
        let evidence_ticket = sample_service_ticket_session(&user_tgt);
        let mut service_tgt = current_tgt_session(5, 180);
        service_tgt.client = sample_service_principal();
        let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local KDC listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            service_tgt.clone(),
        );

        let task = tokio::spawn(serve_s4u2proxy_tcp_request(
            listener,
            service_tgt.session_key.clone(),
            service_tgt.client.clone(),
            target_service.clone(),
            evidence_ticket.client.clone(),
        ));

        let session = client
            .s4u2proxy_with_options(
                &evidence_ticket,
                target_service.clone(),
                TgsReqOptions::new(timestamp(1_893_553_450), 0x3344_5566).with_etypes(vec![18]),
            )
            .await
            .expect("Tokio client S4U2Proxy succeeds");
        task.await.expect("KDC task succeeds");

        assert_eq!(session.client, evidence_ticket.client);
        assert_eq!(session.service, target_service);
        assert_eq!(client.cached_service_ticket_count(), 0);
    });
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
