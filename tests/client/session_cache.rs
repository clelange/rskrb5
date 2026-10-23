use super::*;

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
    // MIT kvno can store host-based service tickets as NT-PRINCIPAL in ccache.
    service_credential.server.name_type = 1;
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
    let now = timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time is after unix epoch")
            .as_secs(),
    );
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
fn tokio_client_prefers_freshest_cached_service_ticket() {
    let tgt = current_tgt_session(5, 180);
    let service_session = |remaining_minutes: u64, ticket: &[u8]| {
        let now = SystemTime::now();
        let mut service_ticket = sample_service_ticket_session(&tgt);
        service_ticket.ticket = ticket.to_vec();
        service_ticket.auth_time = now
            .checked_sub(Duration::from_secs(5 * 60))
            .expect("auth time");
        service_ticket.start_time = service_ticket.auth_time;
        service_ticket.end_time = now
            .checked_add(Duration::from_secs(remaining_minutes * 60))
            .expect("end time");
        service_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(24 * 60 * 60))
                .expect("renew time"),
        );
        service_ticket
    };
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

    client.cache_service_ticket(service_session(120, b"service-long"));
    client.cache_service_ticket(service_session(30, b"service-short"));
    assert_eq!(
        client
            .cached_service_ticket(sample_service_principal())
            .expect("longer service ticket remains")
            .ticket
            .as_slice(),
        b"service-long"
    );

    client.cache_service_ticket(service_session(180, b"service-longer"));
    assert_eq!(
        client
            .cached_service_ticket(sample_service_principal())
            .expect("longer service ticket is selected")
            .ticket
            .as_slice(),
        b"service-longer"
    );
    assert_eq!(client.cached_service_ticket_count(), 1);
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
    let now = timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time is after unix epoch")
            .as_secs(),
    );
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
fn tokio_client_exposes_fast_negotiation_setting() {
    let client = TokioClient::with_password(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "testuser1"),
        TESTUSER_PASSWORD,
    )
    .with_fast_negotiation(false);

    assert!(!client.fast_negotiation());
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
fn tokio_client_auto_renewal_paces_cache_only_nonrenewable_tgt() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused runtime");
        runtime.block_on(async move {
            // Due (55 min old, 5 min left) but not renewable, and cache-only:
            // the refresh is a successful no-op that must be paced.
            let mut tgt = current_tgt_session(55, 5);
            tgt.renew_till = None;
            let client = std::sync::Arc::new(tokio::sync::Mutex::new(
                TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt),
            ));
            let renewal =
                TokioClient::spawn_auto_renewal_with_retry(client, Duration::from_millis(50));

            // With auto-advanced paused time, a paced loop lets this sleep
            // complete; a spinning loop keeps the runtime busy instead.
            tokio::time::sleep(Duration::from_secs(600)).await;
            renewal.abort();
            done.send(()).expect("pacing result reported");
        });
    });

    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the auto-renewal loop paces instead of spinning");
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_refresh_due_uses_current_ticket_life() {
    let now = SystemTime::now();
    let mut renewed = current_tgt_session(60 * 60, 10 * 60);
    renewed.start_time = now
        .checked_sub(Duration::from_secs(60))
        .expect("recent start time");

    let client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, renewed.clone());
    assert!(
        !client.tgt_refresh_due(),
        "a ticket renewed 60 s ago with 10 h left is not due from a 60 h old auth_time"
    );

    let mut near_end = renewed;
    near_end.end_time = now
        .checked_add(Duration::from_secs(10))
        .expect("near end time");
    near_end.key_expiration = Some(near_end.end_time);
    let client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, near_end);
    assert!(
        client.tgt_refresh_due(),
        "the current life, not auth_time, drives the refresh band"
    );
}

#[cfg(feature = "tokio")]
fn spawn_counting_kdc(
    listener: tokio::net::TcpListener,
    client_principal: Principal,
    password: Vec<u8>,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    spawn_counting_kdc_with_tgs_reply(listener, client_principal, password, |_, _, _| {
        krb_error_bytes(32)
    })
}

/// Counting KDC that answers each TGS-REQ through `tgs_reply`, which receives
/// the decoded request, its DER and the number of AS-REQs served before it.
#[cfg(feature = "tokio")]
fn spawn_counting_kdc_with_tgs_reply<F>(
    listener: tokio::net::TcpListener,
    client_principal: Principal,
    password: Vec<u8>,
    tgs_reply: F,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
)
where
    F: Fn(rasn_kerberos::TgsReq, &[u8], usize) -> Vec<u8> + Send + 'static,
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let as_requests = std::sync::Arc::new(AtomicUsize::new(0));
    let tgs_requests = std::sync::Arc::new(AtomicUsize::new(0));
    let as_count = as_requests.clone();
    let tgs_count = tgs_requests.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut header = [0u8; 4];
            if socket.read_exact(&mut header).await.is_err() {
                continue;
            }
            let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
            if socket.read_exact(&mut body).await.is_err() {
                continue;
            }
            let reply = match body.first().copied() {
                // AS-REQ and TGS-REQ application tags.
                Some(0x6a) => {
                    as_count.fetch_add(1, Ordering::SeqCst);
                    let decoded: rasn_kerberos::AsReq =
                        rasn::der::decode(&body).expect("AS-REQ decodes");
                    let built = built_request_from_der(decoded, &body);
                    let reply_key = derive_password_reply_key(
                        &client_principal,
                        &password,
                        &password_key_info(),
                    )
                    .expect("reply key derives");
                    synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce,
                        built.service.clone(),
                        &reply_key,
                    )
                }
                Some(0x6c) => {
                    tgs_count.fetch_add(1, Ordering::SeqCst);
                    let decoded: rasn_kerberos::TgsReq =
                        rasn::der::decode(&body).expect("TGS-REQ decodes");
                    tgs_reply(decoded, &body, as_count.load(Ordering::SeqCst))
                }
                _ => continue,
            };
            let mut response = Vec::with_capacity(4 + reply.len());
            response.extend_from_slice(&(reply.len() as u32).to_be_bytes());
            response.extend_from_slice(&reply);
            let _ = socket.write_all(&response).await;
        }
    });
    (handle, as_requests, tgs_requests)
}

#[cfg(feature = "tokio")]
fn krb_error_bytes(error_code: i32) -> Vec<u8> {
    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code,
        crealm: Some(realm("TEST.GOKRB5")),
        cname: Some(rasn_principal(&Principal::user("TEST.GOKRB5", "testuser1"))),
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&Principal::tgt_service("TEST.GOKRB5")),
        e_text: None,
        e_data: None,
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

#[cfg(feature = "tokio")]
fn expired_renewable_tgt() -> rskrb5::client::AsRepSession {
    let now = SystemTime::now();
    let mut tgt = current_tgt_session(120, 0);
    tgt.renew_till = Some(
        now.checked_add(Duration::from_secs(60 * 60))
            .expect("renew till"),
    );
    tgt
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_affirm_login_falls_back_to_as_for_expired_renewable_tgt() {
    runtime().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
            listener,
            client_principal.clone(),
            TESTUSER_PASSWORD.to_vec(),
        );

        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            expired_renewable_tgt(),
        )
        .with_password_credential(TESTUSER_PASSWORD);

        client
            .affirm_login()
            .await
            .expect("expired renewable TGT recovers through the AS exchange");
        assert!(as_requests.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        assert_eq!(
            tgs_requests.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an expired TGT with a credential goes straight to the AS exchange"
        );
        kdc.abort();
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_refresh_tgt_if_needed_falls_back_to_as_for_expired_renewable_tgt() {
    runtime().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
            listener,
            client_principal.clone(),
            TESTUSER_PASSWORD.to_vec(),
        );

        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            expired_renewable_tgt(),
        )
        .with_password_credential(TESTUSER_PASSWORD);

        client
            .refresh_tgt_if_needed()
            .await
            .expect("refresh recovers through the AS exchange");
        assert!(as_requests.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        assert_eq!(
            tgs_requests.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "expired renewable TGTs do not spend a doomed TGS renewal first"
        );
        kdc.abort();
    });
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_cache_only_expired_renewable_tgt_keeps_renewal_error() {
    runtime().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
            listener,
            client_principal.clone(),
            TESTUSER_PASSWORD.to_vec(),
        );

        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            expired_renewable_tgt(),
        );

        client
            .affirm_login()
            .await
            .expect_err("cache-only client keeps the renewal error");
        assert_eq!(as_requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            tgs_requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "cache-only clients still attempt the in-grace renewal"
        );
        kdc.abort();
    });
}

/// Run `test` on a paused current-thread runtime in its own thread and return
/// its report, failing after 10 s of real time so a spinning loop cannot hang.
#[cfg(feature = "tokio")]
fn run_on_paused_runtime<T, F, Fut>(test: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T>,
{
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused runtime");
        let report = runtime.block_on(test());
        done.send(report).expect("paused-clock report delivered");
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the paused-clock test reports within 10 s of real time")
}

#[cfg(feature = "tokio")]
fn is_renewal_request(request: &rasn_kerberos::TgsReq) -> bool {
    <[u8; 4]>::try_from(request.0.req_body.kdc_options.0.as_raw_slice())
        .is_ok_and(|options| u32::from_be_bytes(options) & KDC_OPTION_RENEW != 0)
}

#[cfg(feature = "tokio")]
fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .expect("time is after the epoch")
        .as_secs()
}

/// TGS-REP renewing the primary TGT the way RFC 4120 renewal does: `auth_time`
/// stays 60 h old while `start_time` restarts a 10 h ticket life now. The
/// session key is unchanged, so every later renewal decrypts with it too.
#[cfg(feature = "tokio")]
fn renewed_tgt_reply_keeping_auth_time(request: rasn_kerberos::TgsReq, der: &[u8]) -> Vec<u8> {
    let built = built_tgs_request_from_der(request, der);
    let now = unix_seconds(SystemTime::now());
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SESSION_KEY),
    };
    let enc_part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_encryption_key(&session_key),
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(now),
        }],
        nonce: built.nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(TICKET_FLAGS)),
        auth_time: kerberos_time(now - 60 * 60 * 60),
        start_time: Some(kerberos_time(now)),
        end_time: kerberos_time(now + 10 * 60 * 60),
        renew_till: Some(kerberos_time(now + 7 * 24 * 60 * 60)),
        srealm: realm(&built.service.realm),
        sname: rasn_principal(&built.service),
        caddr: None,
        encrypted_pa_data: None,
    });
    let encrypted = encrypt_message(
        &session_key,
        &rasn::der::encode(&enc_part).expect("EncTgsRepPart encodes"),
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
        TGS_REP_CONFOUNDER,
    );
    let tgs_rep = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(13),
        padata: None,
        crealm: realm(&built.client.realm),
        cname: rasn_principal(&built.client),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: rasn::types::Integer::from(5),
            realm: realm(&built.service.realm),
            sname: rasn_principal(&built.service),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: [0xde, 0xad, 0xbe, 0xef].as_slice().into(),
            },
        },
        enc_part: rasn_kerberos::EncryptedData {
            etype: session_key.etype,
            kvno: None,
            cipher: encrypted.into(),
        },
    });
    rasn::der::encode(&tgs_rep).expect("TGS-REP encodes")
}

/// After a renewal that keeps an old `auth_time`, auto-renewal measures the
/// refresh band from the renewed ticket's own life and sleeps instead of
/// renewing again.
#[cfg(feature = "tokio")]
#[test]
fn tokio_client_auto_renewal_paces_after_renewal() {
    let (as_requests, renewal_requests) = run_on_paused_runtime(|| async {
        use std::sync::atomic::Ordering;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc_with_tgs_reply(
            listener,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD.to_vec(),
            |request, der, _| renewed_tgt_reply_keeping_auth_time(request, der),
        );

        // Due (55 min old, 5 min left) and renewable; cache-only, so only a
        // renewal can refresh it.
        let client = std::sync::Arc::new(tokio::sync::Mutex::new(TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            current_tgt_session(55, 5),
        )));
        let renewal = TokioClient::spawn_auto_renewal(client.clone());

        // Spin without timers until the first renewal is installed: an idle
        // paused runtime auto-advances the clock while loopback I/O is still
        // in flight, which would fire the transport timeout.
        let renewed_life_floor = Duration::from_secs(60 * 60);
        loop {
            let renewed = tgs_requests.load(Ordering::SeqCst) >= 1
                && client.try_lock().is_ok_and(|client| {
                    client.tgt_session().is_some_and(|tgt| {
                        tgt.end_time
                            .duration_since(SystemTime::now())
                            .is_ok_and(|left| left > renewed_life_floor)
                    })
                });
            if renewed {
                break;
            }
            tokio::task::yield_now().await;
        }

        // 600 s of virtual time in 1 s steps; a loop that still treats the
        // renewed ticket as due renews again on every step.
        for _ in 0..600 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        renewal.abort();
        kdc.abort();
        (
            as_requests.load(Ordering::SeqCst),
            tgs_requests.load(Ordering::SeqCst),
        )
    });

    assert_eq!(as_requests, 0, "a cache-only client never logs in");
    assert_eq!(
        renewal_requests, 1,
        "a renewal with a fresh 10 h life is not due again within 600 s"
    );
}

/// When the KDC refuses to renew a due TGT, auto-renewal with a configured
/// password falls back to a fresh AS exchange instead of retrying the renewal.
#[cfg(feature = "tokio")]
#[test]
fn tokio_client_auto_renewal_uses_as_when_renewal_refused() {
    let (as_requests, renewal_requests) = run_on_paused_runtime(|| async {
        use std::sync::atomic::Ordering;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
            listener,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD.to_vec(),
        );

        // The paused clock auto-advances while loopback I/O is in flight, so
        // keep the transport timeout beyond the 600 s window: the renewal must
        // fail on the KDC's refusal, not on a virtual timeout.
        let client = std::sync::Arc::new(tokio::sync::Mutex::new(
            TokioClient::from_tgt_session(
                config_with_kdc_server(addr.to_string()),
                KdcProtocol::Tcp,
                current_tgt_session(55, 5),
            )
            .with_password_credential(TESTUSER_PASSWORD)
            .with_transport(
                TokioKdcTransport::new().with_timeout(Duration::from_secs(24 * 60 * 60)),
            ),
        ));
        let renewal = TokioClient::spawn_auto_renewal(client);

        for _ in 0..600 {
            if as_requests.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        renewal.abort();
        kdc.abort();
        (
            as_requests.load(Ordering::SeqCst),
            tgs_requests.load(Ordering::SeqCst),
        )
    });

    assert!(
        renewal_requests >= 1,
        "the due TGT is offered for renewal first"
    );
    assert!(
        as_requests >= 1,
        "a refused renewal falls back to the AS exchange within 600 s"
    );
}

/// `get_service_ticket` with an expired renewable TGT and a password skips the
/// renewal a conforming KDC refuses, logs in through AS, then requests the
/// service ticket with the fresh TGT.
#[cfg(feature = "tokio")]
#[test]
fn tokio_client_get_service_ticket_falls_back_to_as_for_expired_renewable_tgt() {
    runtime().block_on(async {
        use std::sync::atomic::Ordering;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind kdc listener");
        let addr = listener.local_addr().expect("kdc address");
        let tgt_session_key = EncryptionKey {
            etype: 18,
            value: decode_hex(SESSION_KEY),
        };
        let (kdc, as_requests, tgs_requests) = spawn_counting_kdc_with_tgs_reply(
            listener,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD.to_vec(),
            move |request, der, as_requests_before| {
                // KDC_ERR_TKT_EXPIRED for a renewal of the expired TGT, and for
                // a service request that did not follow the AS exchange.
                if is_renewal_request(&request) || as_requests_before == 0 {
                    return krb_error_bytes(32);
                }
                let built = built_tgs_request_from_der(request, der);
                synthetic_tgs_rep(&built, built.nonce, &tgt_session_key)
            },
        );

        let mut client = TokioClient::from_tgt_session(
            config_with_kdc_server(addr.to_string()),
            KdcProtocol::Tcp,
            expired_renewable_tgt(),
        )
        .with_password_credential(TESTUSER_PASSWORD);

        let ticket = client
            .get_service_ticket(sample_service_principal())
            .await
            .expect("the service ticket is acquired after an AS login");
        assert_eq!(ticket.service, sample_service_principal());
        assert_eq!(as_requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            tgs_requests.load(Ordering::SeqCst),
            1,
            "only the service TGS-REQ follows the AS exchange; no doomed renewal"
        );
        kdc.abort();
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

#[cfg(all(feature = "tokio", feature = "spnego"))]
#[test]
fn negotiate_client_builds_authorization_header_for_host_from_ccache_name() {
    let (path, name) = save_sample_negotiate_ccache("negotiate-load-name");

    let mut client =
        NegotiateClient::from_ccache_name(Config::new(), &name).expect("negotiate client loads");
    assert_eq!(client.inner().protocol(), KdcProtocol::Auto);
    let header = runtime()
        .block_on(client.authorization_header_for_host("HTTP", "host.test.gokrb5"))
        .expect("authorization header builds");
    let _ = std::fs::remove_file(&path);

    assert!(header.starts_with("Negotiate "));
    rskrb5::spnego::parse_negotiate_header(&header).expect("SPNEGO header parses");
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
#[test]
fn blocking_negotiate_client_builds_authorization_header_for_host_from_ccache_name() {
    let (path, name) = save_sample_negotiate_ccache("blocking-negotiate-load-name");

    let mut client = BlockingNegotiateClient::from_ccache_name(Config::new(), &name)
        .expect("blocking negotiate client loads");
    let header = client
        .authorization_header_for_host("HTTP", "host.test.gokrb5")
        .expect("blocking authorization header builds");
    let _ = std::fs::remove_file(&path);

    assert!(header.starts_with("Negotiate "));
    rskrb5::spnego::parse_negotiate_header(&header).expect("SPNEGO header parses");
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
#[test]
fn negotiate_client_preserves_unsupported_cache_type_error() {
    let error = NegotiateClient::from_ccache_name(Config::new(), "API:")
        .expect_err("unsupported cache type rejected");

    assert!(matches!(
        error,
        Error::CCache(ccache::Error::UnsupportedCacheType { cache_type })
            if cache_type == "API"
    ));
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

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_rejects_non_tgt_session_cache_insert() {
    let tgt = current_tgt_session(5, 180);
    let service_ticket = sample_service_ticket_session(&tgt);
    let mut client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);

    let error = client
        .cache_tgt_session(service_ticket)
        .expect_err("service ticket is rejected as a TGT session");

    assert!(matches!(
        error,
        Error::InvalidTgtSession { service } if service == "HTTP/host.test.gokrb5"
    ));
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_client_prefers_freshest_cached_tgt_session() {
    let primary_session = |remaining_minutes: u64, ticket: &[u8]| {
        let mut tgt = current_tgt_session(5, remaining_minutes);
        tgt.ticket = ticket.to_vec();
        tgt
    };
    let referral_session = |remaining_minutes: u64, ticket: &[u8]| {
        let mut tgt = primary_session(remaining_minutes, ticket);
        tgt.service = Principal::new(
            "TEST.GOKRB5",
            2,
            ["krbtgt".to_owned(), "RESDOM.GOKRB5".to_owned()],
        );
        tgt
    };

    let primary_tgt = primary_session(120, b"primary-long");
    let mut client =
        TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, primary_tgt.clone());

    client
        .cache_tgt_session(primary_session(30, b"primary-short"))
        .expect("shorter primary TGT caches");
    assert_eq!(
        client
            .tgt_session()
            .expect("primary TGT remains")
            .ticket
            .as_slice(),
        b"primary-long"
    );
    assert_eq!(
        client
            .tgt_session_for_realm("TEST.GOKRB5")
            .expect("realm-keyed primary remains")
            .ticket
            .as_slice(),
        b"primary-long"
    );

    client
        .cache_tgt_session(primary_session(180, b"primary-longer"))
        .expect("longer primary TGT caches");
    assert_eq!(
        client
            .tgt_session()
            .expect("primary TGT is replaced")
            .ticket
            .as_slice(),
        b"primary-longer"
    );

    client
        .cache_tgt_session(referral_session(90, b"referral-long"))
        .expect("referral TGT caches");

    client
        .cache_tgt_session(referral_session(15, b"referral-short"))
        .expect("shorter referral TGT caches");
    assert_eq!(
        client
            .tgt_session_for_realm("RESDOM.GOKRB5")
            .expect("longer referral TGT remains")
            .ticket
            .as_slice(),
        b"referral-long"
    );

    client
        .cache_tgt_session(referral_session(180, b"referral-longer"))
        .expect("longer referral TGT caches");
    assert_eq!(
        client
            .tgt_session_for_realm("RESDOM.GOKRB5")
            .expect("longer referral TGT is selected")
            .ticket
            .as_slice(),
        b"referral-longer"
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
