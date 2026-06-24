use super::*;

#[test]
fn parses_kdc_preauth_required_error_and_selects_etype_info2() {
    let error_bytes = synthetic_preauth_required_error();

    let error = process_kdc_error(&error_bytes).expect("KRB-ERROR decodes");

    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    assert_eq!(error.ctime, None);
    assert_eq!(error.cusec, None);
    assert_eq!(error.stime, timestamp(1_893_553_440));
    assert_eq!(error.susec, 0);
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
        ctime: None,
        cusec: None,
        stime: timestamp(1_893_553_440),
        susec: 0,
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
fn login_tgt_with_password_can_disable_fast_negotiation_marker() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_etypes(vec![18])
        .with_fast_negotiation(false);
    let key_info = password_key_info();
    let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
        .expect("password key derives");
    let mut transport = PreauthTransport::new(reply_key, None).with_fast_negotiation(false);

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
fn login_tgt_with_keytab_can_disable_fast_negotiation_marker() {
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let options = AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344)
        .with_etypes(vec![18])
        .with_fast_negotiation(false);
    let keytab = keytab_with_reply_key(7);
    let mut transport = PreauthTransport::new(reply_key(), Some(7)).with_fast_negotiation(false);

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
