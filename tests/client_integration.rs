#![cfg(feature = "tokio")]

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rskrb5::ccache::CCache;
use rskrb5::client::{
    AsReqOptions, Error as ClientError, KdcProtocol, PreauthKeyInfo, Principal, TgsReqOptions,
    TokioClient, TokioKdcTransport, build_tgs_req, build_tgt_as_req, derive_password_reply_key,
    pa_enc_timestamp_with_confounder,
};
use rskrb5::config::Config;
use rskrb5::crypto::{AesSha1Etype, Des3CbcSha1KdEtype};
use rskrb5::kadmin::{KPASSWD_SUCCESS, ipv4_host_address};
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};

const REALM: &str = "TEST.GOKRB5";
const USER: &str = "testuser1";
const PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER1_SALT: &[u8] = b"TEST.GOKRB5testuser1";
const AES128_ETYPE: i32 = 17;
const AES256_ETYPE: i32 = 18;
const AES128_SHA2_ETYPE: i32 = 19;
const AES256_SHA2_ETYPE: i32 = 20;
const DES3_ETYPE: i32 = 16;
const RC4_HMAC_ETYPE: i32 = 23;
const TESTUSER1_KVNO: u32 = 2;
const SERVICE_HOST: &str = "host.test.gokrb5";
const RESDOM_REALM: &str = "RESDOM.GOKRB5";
const RESDOM_SERVICE_HOST: &str = "host.resdom.gokrb5";
const TEMP_PASSWORD: &[u8] = b"passwordvalue-rskrb5-temp";
const KEYTAB_TESTUSER2_TEST_GOKRB5: &str = "05020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240010011001086824c55ff5de30386dd83dc62b44bb7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240020011001086824c55ff5de30386dd83dc62b44bb7000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001300106ccff358aaa8a4a41c444e173b1463c2000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001300106ccff358aaa8a4a41c444e173b1463c2000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd700000002000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400100100018bc025746e9e66bd6b62a918f6413d529803192a28aabf79200000001000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400200100018bc025746e9e66bd6b62a918f6413d529803192a28aabf792000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200170010084768c373663b3bef1f6385883cf7ff00000002";
const KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD: &str = "0502000000370001000b544553542e474f4b52423500097465737475736572310000000158ef4bc5010011001039a9a382153105f8708e80f93382654e000000470001000b544553542e474f4b52423500097465737475736572310000000158ef4bc60100120020fc5bb940d6075214e0c6fc0456ce68c33306094198a927b4187d7cf3f4aea50d";
static INTEGRATION_LOCK: Mutex<()> = Mutex::new(());
#[cfg(feature = "spnego")]
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

#[test]
fn docker_mit_kdc_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC AS login over {protocol:?} to {addr}");
            let key = testuser_reply_key()?;
            let request = build_login_request(protocol, key.clone())?;
            let session = transport
                .exchange_as_req(protocol, addr.as_str(), &request, &key)
                .await?;

            assert_eq!(session.client, Principal::user(REALM, USER));
            assert_eq!(session.service, Principal::tgt_service(REALM));
            assert_eq!(session.session_key.etype, AES256_ETYPE);
            assert!(!session.session_key.value.is_empty());
            assert!(!session.ticket.is_empty());
            assert!(session.end_time > session.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_negotiated_as_login_with_password_and_keytab() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
        let keytab = testuser_keytab()?;

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running negotiated Docker KDC password AS login over {protocol:?} to {addr}"
            );
            let password_session = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 1)?,
                )
                .await?;
            assert_login_session(password_session);

            eprintln!("running negotiated Docker KDC keytab AS login over {protocol:?} to {addr}");
            let keytab_session = transport
                .login_tgt_with_keytab(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    &keytab,
                    login_options(protocol, 2)?,
                )
                .await?;
            assert_login_session(keytab_session);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_rc4_hmac_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC RC4-HMAC AS login over {protocol:?} to {addr}");
            let session = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 14, vec![RC4_HMAC_ETYPE])?,
                )
                .await?;

            assert_eq!(session.client, Principal::user(REALM, USER));
            assert_eq!(session.service, Principal::tgt_service(REALM));
            assert_eq!(session.session_key.etype, RC4_HMAC_ETYPE);
            assert!(!session.session_key.value.is_empty());
            assert!(!session.ticket.is_empty());
            assert!(session.end_time > session.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_des3_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC DES3 AS login over {protocol:?} to {addr}");
            let session = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 19, vec![DES3_ETYPE])?,
                )
                .await?;

            assert_eq!(session.client, Principal::user(REALM, USER));
            assert_eq!(session.service, Principal::tgt_service(REALM));
            assert_eq!(session.session_key.etype, DES3_ETYPE);
            assert_eq!(
                session.session_key.value.len(),
                Des3CbcSha1KdEtype.key_len()
            );
            assert!(!session.ticket.is_empty());
            assert!(session.end_time > session.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_configured_kdc_as_login() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kdc_config()?;
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
        let keytab = testuser_keytab()?;

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            let endpoints = transport.discover_kdcs(&config, REALM, protocol).await?;
            eprintln!(
                "running config-discovered Docker KDC AS login over {protocol:?}: {endpoints:?}"
            );
            assert_eq!(endpoints.len(), 1);

            let password_session = transport
                .login_tgt_with_password_config(
                    &config,
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 7)?,
                )
                .await?;
            assert_login_session(password_session);

            let keytab_session = transport
                .login_tgt_with_keytab_config(
                    &config,
                    protocol,
                    Principal::user(REALM, USER),
                    &keytab,
                    login_options(protocol, 8)?,
                )
                .await?;
            assert_login_session(keytab_session);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_rejects_wrong_keytab_login() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_keytab(
            configured_kdc_config()?,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            keytab_from_hex(KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD)?,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

        assert!(
            client.login().await.is_err(),
            "login with an incorrect keytab must fail"
        );

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_keytab_login_for_preauth_user() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let keytab = keytab_from_hex(KEYTAB_TESTUSER2_TEST_GOKRB5)?;
        for protocol in [KdcProtocol::Auto, KdcProtocol::Tcp] {
            let mut client = TokioClient::with_keytab(
                configured_kdc_config()?,
                protocol,
                Principal::user(REALM, "testuser2"),
                keytab.clone(),
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let session = client.login().await?;

            assert_eq!(session.client, Principal::user(REALM, "testuser2"));
            assert_eq!(session.service, Principal::tgt_service(REALM));
            assert_eq!(session.session_key.etype, AES256_ETYPE);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_invalid_service_principal_returns_kdc_error() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_keytab(
            configured_kdc_config()?,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            testuser_keytab()?,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        client.login().await?;
        let error = client
            .get_service_ticket(Principal::new(REALM, 2, ["host.test.gokrb5"]))
            .await
            .expect_err("invalid service principal must be rejected");

        match error {
            ClientError::Kdc(kdc_error) => assert_eq!(kdc_error.error_code, 7),
            other => panic!("expected KDC service-principal error, got {other:?}"),
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tcp_login_fails_for_unreachable_kdc() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_keytab(
            configured_kdc_config_with_primary_realm_kdcs(&[closed_tcp_kdc_addr()])?,
            KdcProtocol::Tcp,
            Principal::user(REALM, USER),
            testuser_keytab()?,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

        assert!(
            client.login().await.is_err(),
            "login through an unreachable KDC must fail"
        );

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tcp_login_tries_next_configured_kdc() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_keytab(
            configured_kdc_config_with_primary_realm_kdcs(&[closed_tcp_kdc_addr(), kdc_addr()])?,
            KdcProtocol::Tcp,
            Principal::user(REALM, USER),
            testuser_keytab()?,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let session = client.login().await?;

        assert_login_session(session.clone());

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_password_cache() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kdc_config()?;

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running high-level Tokio client cached TGS flow over {protocol:?}");
            let mut client = TokioClient::with_password(
                config.clone(),
                protocol,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            let service = service_principal();
            let first = client.get_service_ticket(service.clone()).await?;
            let second = client.get_service_ticket(service.clone()).await?;

            assert_eq!(client.client_principal(), &Principal::user(REALM, USER));
            assert!(client.tgt_session().is_some());
            assert_eq!(client.cached_service_ticket_count(), 1);
            assert_eq!(first, second);
            assert_eq!(first.client, Principal::user(REALM, USER));
            assert_eq!(first.service, service);
            assert_eq!(first.session_key.etype, AES256_ETYPE);
            assert!(!first.ticket.is_empty());
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_destroy_clears_live_state() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let service = service_principal();
        let mut client = TokioClient::with_keytab(
            configured_kdc_config()?,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            testuser_keytab()?,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        client.login().await?;
        let ticket = client.get_service_ticket(service.clone()).await?;

        assert_login_session(client.tgt_session().expect("TGT is cached").clone());
        assert_eq!(ticket.service, service);
        assert_eq!(client.cached_service_ticket_count(), 1);
        assert!(client.cached_service_ticket(service.clone()).is_some());

        client.destroy();

        assert!(client.tgt_session().is_none());
        assert_eq!(client.tgt_session_count(), 0);
        assert_eq!(client.cached_service_ticket_count(), 0);
        assert!(client.cached_service_ticket(service).is_none());
        let error = match client.login().await {
            Ok(_) => panic!("destroyed client must not log in without credentials"),
            Err(error) => error,
        };
        assert!(matches!(error, ClientError::NoClientCredentials));

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_change_password() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    if std::env::var("TEST_KPASSWD").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC kpasswd test; set TEST_KPASSWD=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kpasswd_config()?;
        let protocol = KdcProtocol::Tcp;

        if password_login(&config, protocol, PASSWORD).await.is_err() {
            eprintln!(
                "original Docker KDC password did not authenticate; attempting temp-password restore"
            );
            change_password_once(&config, protocol, TEMP_PASSWORD, PASSWORD).await?;
            password_login(&config, protocol, PASSWORD).await?;
        }

        eprintln!("running high-level Tokio client kpasswd change over {protocol:?}");
        let mut client = TokioClient::with_password(
            config.clone(),
            protocol,
            Principal::user(REALM, USER),
            PASSWORD.to_vec(),
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

        let changed = client
            .change_password(TEMP_PASSWORD, kpasswd_sender_address()?)
            .await?;
        assert_eq!(changed.code, KPASSWD_SUCCESS);

        let restored = client
            .change_password(PASSWORD, kpasswd_sender_address()?)
            .await?;
        assert_eq!(restored.code, KPASSWD_SUCCESS);

        let session = password_login(&config, protocol, PASSWORD).await?;
        assert_login_session(session);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_dns_srv_as_login() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    if std::env::var("TEST_DNS_KDC").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC DNS integration test; set TEST_DNS_KDC=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = dns_kdc_config()?;
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            let endpoints = transport.discover_kdcs(&config, REALM, protocol).await?;
            eprintln!("running DNS SRV Docker KDC AS login over {protocol:?}: {endpoints:?}");
            assert!(
                endpoints
                    .iter()
                    .all(|endpoint| endpoint.source == rskrb5::client::KdcEndpointSource::DnsSrv)
            );

            let session = transport
                .login_tgt_with_password_config(
                    &config,
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 9)?,
                )
                .await?;
            assert_login_session(session);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC TGS service-ticket exchange over {protocol:?} to {addr}");
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 3)?,
                )
                .await?;
            assert_login_session(tgt.clone());

            let service = service_principal();
            let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 4)?)?;
            let ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, AES256_ETYPE);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_auto_as_tgs_service_ticket() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
        let protocol = KdcProtocol::Auto;

        eprintln!("running Docker KDC auto AS/TGS exchange to {addr}");
        let tgt = transport
            .login_tgt_with_password(
                protocol,
                addr.as_str(),
                Principal::user(REALM, USER),
                PASSWORD,
                login_options(protocol, 47)?,
            )
            .await?;
        assert_login_session(tgt.clone());

        let service = service_principal();
        let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 48)?)?;
        let ticket = transport
            .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
            .await?;

        assert_eq!(ticket.client, Principal::user(REALM, USER));
        assert_eq!(ticket.service, service);
        assert_eq!(ticket.session_key.etype, AES256_ETYPE);
        assert!(!ticket.session_key.value.is_empty());
        assert!(!ticket.ticket.is_empty());
        assert!(ticket.end_time > ticket.start_time);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_aes128_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC AES128 AS/TGS exchange over {protocol:?} to {addr}");
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 27, vec![AES128_ETYPE])?,
                )
                .await?;
            assert_eq!(tgt.session_key.etype, AES128_ETYPE);
            assert!(!tgt.session_key.value.is_empty());

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, 28, vec![AES128_ETYPE])?,
            )?;
            let ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, AES128_ETYPE);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_rc4_hmac_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC RC4-HMAC TGS service-ticket exchange over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 15, vec![RC4_HMAC_ETYPE])?,
                )
                .await?;
            assert_eq!(tgt.session_key.etype, RC4_HMAC_ETYPE);

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, 16, vec![RC4_HMAC_ETYPE])?,
            )?;
            let ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, RC4_HMAC_ETYPE);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_des3_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC DES3 TGS service-ticket exchange over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 20, vec![DES3_ETYPE])?,
                )
                .await?;
            assert_eq!(tgt.session_key.etype, DES3_ETYPE);

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, 21, vec![DES3_ETYPE])?,
            )?;
            let ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, DES3_ETYPE);
            assert_eq!(ticket.session_key.value.len(), Des3CbcSha1KdEtype.key_len());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_old_kdc_password_and_keytab_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>>
{
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = old_kdc_addr();
        assert_password_as_tgs_for_etypes(&addr, &[AES256_ETYPE], 49).await?;
        assert_keytab_as_tgs_for_etypes(&addr, &[AES256_ETYPE], 51).await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_latest_kdc_aes_sha2_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = latest_kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for etype in [AES128_SHA2_ETYPE, AES256_SHA2_ETYPE] {
            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                eprintln!(
                    "running Docker latest-KDC AES-SHA2 etype {etype} AS/TGS exchange over {protocol:?} to {addr}"
                );
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, etype as u32 + 4, vec![etype])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, etype);
                assert!(!tgt.session_key.value.is_empty());

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, etype as u32 + 6, vec![etype])?,
                )?;
                let ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, etype);
                assert!(!ticket.session_key.value.is_empty());
                assert!(!ticket.ticket.is_empty());
                assert!(ticket.end_time > ticket.start_time);
            }
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_keytab_enctype_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(assert_keytab_as_tgs_for_etypes(
        &kdc_addr(),
        &[AES128_ETYPE, AES256_ETYPE, DES3_ETYPE, RC4_HMAC_ETYPE],
        29,
    ))
}

#[test]
fn docker_mit_latest_kdc_keytab_aes_sha2_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>>
{
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(assert_keytab_as_tgs_for_etypes(
        &latest_kdc_addr(),
        &[AES128_SHA2_ETYPE, AES256_SHA2_ETYPE],
        45,
    ))
}

#[test]
fn docker_mit_kdc_loads_external_kinit_ccache() -> Result<(), Box<dyn Error>> {
    if !privileged_integration_enabled() {
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    let env = ExternalKrbEnv::new("load-kinit")?;
    env.kinit()?;
    let cache = CCache::load_name(&env.ccache_name)?;

    assert_eq!(cache.default_principal().name_string(), USER);
    assert_eq!(cache.default_principal().realm, REALM);
    assert!(cache.contains_server(&["krbtgt", REALM]));

    Ok(())
}

#[test]
fn docker_mit_kdc_reads_external_kvno_service_ticket_ccache() -> Result<(), Box<dyn Error>> {
    if !privileged_integration_enabled() {
        return Ok(());
    }
    if !privileged_kvno_integration_enabled() {
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    let env = ExternalKrbEnv::new("kvno-service")?;
    env.kinit()?;
    env.kvno(&format!("HTTP/{SERVICE_HOST}"))?;
    let cache = CCache::load_name(&env.ccache_name)?;

    assert!(cache.contains_server(&["HTTP", SERVICE_HOST]));
    let service = cache
        .get_entry(&["HTTP", SERVICE_HOST])
        .expect("HTTP service ticket is cached");
    assert_eq!(service.server.realm, REALM);
    assert_eq!(service.key.etype, AES256_ETYPE);

    Ok(())
}

#[test]
fn docker_mit_kdc_tokio_client_uses_external_ccache_tgt() -> Result<(), Box<dyn Error>> {
    if !privileged_integration_enabled() {
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    let env = ExternalKrbEnv::new("client-tgt")?;
    env.kinit()?;
    let cache = CCache::load_name(&env.ccache_name)?;

    runtime().block_on(async {
        let mut client =
            TokioClient::from_ccache(configured_kdc_config()?, KdcProtocol::Auto, &cache)
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let first = client.get_service_ticket(service_principal()).await?;
        let second = client.get_service_ticket(service_principal()).await?;

        assert_eq!(first, second);
        assert_eq!(first.client, Principal::user(REALM, USER));
        assert_eq!(first.service, service_principal());
        assert_eq!(first.session_key.etype, AES256_ETYPE);
        assert_eq!(client.cached_service_ticket_count(), 1);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_uses_cached_service_ticket_without_kdc() -> Result<(), Box<dyn Error>>
{
    if !privileged_integration_enabled() {
        return Ok(());
    }
    if !privileged_kvno_integration_enabled() {
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    let env = ExternalKrbEnv::new("client-cached-service")?;
    env.kinit()?;
    env.kvno(&format!("HTTP/{SERVICE_HOST}"))?;
    let cache = CCache::load_name(&env.ccache_name)?;

    runtime().block_on(async {
        let mut client = TokioClient::from_ccache(Config::new(), KdcProtocol::Auto, &cache)
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let ticket = client.get_service_ticket(service_principal()).await?;

        assert_eq!(ticket.client, Principal::user(REALM, USER));
        assert_eq!(ticket.service, service_principal());
        assert_eq!(ticket.session_key.etype, AES256_ETYPE);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tgt_renewal_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = short_kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running Docker KDC TGT renewal over {protocol:?} to {addr}");
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 12)?
                        .with_renew_lifetime(Some(Duration::from_secs(10 * 60))),
                )
                .await?;
            assert_login_session(tgt.clone());
            let original_renew_till = tgt.renew_till.expect("renewable TGT has renew-till");

            let renewed = transport
                .renew_tgt(protocol, addr.as_str(), &tgt, tgs_options(protocol, 13)?)
                .await?;

            assert_login_session(renewed.clone());
            assert_eq!(renewed.service, Principal::tgt_service(REALM));
            assert_eq!(renewed.renew_till, Some(original_renew_till));
            assert!(renewed.end_time <= original_renew_till);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_tgt_renewal() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = short_kdc_config()?;

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running high-level Tokio client TGT renewal over {protocol:?}");
            let mut client = TokioClient::with_password(
                config.clone(),
                protocol,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            let original = client.login().await?.clone();
            let original_renew_till = original.renew_till.expect("renewable TGT has renew-till");
            let renewed = client.renew_tgt().await?.clone();

            assert_login_session(renewed.clone());
            assert_eq!(renewed.service, Principal::tgt_service(REALM));
            assert_eq!(renewed.renew_till, Some(original_renew_till));
            assert!(renewed.end_time <= original_renew_till);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tgs_referral_to_resource_domain() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kdc_config()?;
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC TGS referral exchange over {protocol:?} from {REALM} to {RESDOM_REALM}"
            );
            let tgt = transport
                .login_tgt_with_password_config(
                    &config,
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 10)?,
                )
                .await?;
            assert_login_session(tgt.clone());

            let service = resdom_service_principal();
            let ticket = transport
                .get_service_ticket_with_referrals(
                    &config,
                    protocol,
                    &tgt,
                    service.clone(),
                    tgs_options(protocol, 11)?,
                )
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, AES256_ETYPE);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn docker_mit_kdc_tokio_client_caches_referral_tgt() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kdc_config()?;

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!("running high-level Tokio client TGS referral cache over {protocol:?}");
            let mut client = TokioClient::with_password(
                config.clone(),
                protocol,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            let service = resdom_service_principal();
            let first = client.get_service_ticket(service.clone()).await?;
            let second = client.get_service_ticket(service.clone()).await?;

            assert_eq!(first, second);
            assert_eq!(first.client, Principal::user(REALM, USER));
            assert_eq!(first.service, service);
            assert_eq!(first.session_key.etype, AES256_ETYPE);
            assert!(client.tgt_session().is_some());
            assert!(client.tgt_session_for_realm(RESDOM_REALM).is_some());
            assert_eq!(client.tgt_session_count(), 2);
            assert_eq!(client.cached_service_ticket_count(), 1);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_spnego_header_round_trip_through_service_validator() -> Result<(), Box<dyn Error>>
{
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC SPNEGO client header round-trip over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 5)?,
                )
                .await?;
            let service = service_principal();
            let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 6)?)?;
            let service_ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;
            let context = rskrb5::spnego::init_sec_context(
                &service_ticket,
                rskrb5::spnego::InitiatorContextOptions::new(),
            )?;
            assert_eq!(context.service, service);
            assert!(context.sequence_number.is_some());

            let keytab = http_keytab()?;
            let mut validator =
                rskrb5::service::ServiceValidator::new(&keytab).with_now(SystemTime::now());
            let accepted =
                rskrb5::spnego::accept_sec_context_header(&mut validator, &context.header)?;
            assert_eq!(
                accepted.ap_req.client,
                rskrb5::service::Principal {
                    realm: REALM.to_owned(),
                    name_type: 1,
                    components: vec![USER.to_owned()],
                }
            );
            assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");

            let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let response_header = accepted.ap_rep_response_header_with_confounder(
                &confounder(protocol, elapsed),
                rskrb5::service::ApRepOptions::default(),
            )?;
            let verified = context.verify_ap_rep_response_header(&response_header)?;
            assert_eq!(verified.ctime, context.authenticator_ctime);
            assert_eq!(verified.cusec, context.authenticator_cusec);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_spnego_service_rejects_replayed_headers() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_password(
            configured_kdc_config()?,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            PASSWORD,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let service_ticket = client.get_service_ticket(service_principal()).await?;
        let now = SystemTime::now();
        let first = rskrb5::spnego::init_sec_context_with_confounder(
            &service_ticket,
            rskrb5::spnego::InitiatorContextOptions::new().with_sequence_number(Some(1)),
            now,
            111_111,
            &[0x11; 16],
        )?;
        let second = rskrb5::spnego::init_sec_context_with_confounder(
            &service_ticket,
            rskrb5::spnego::InitiatorContextOptions::new().with_sequence_number(Some(2)),
            now,
            222_222,
            &[0x22; 16],
        )?;

        let keytab = http_keytab()?;
        let mut validator = rskrb5::service::ServiceValidator::new(&keytab).with_now(now);
        rskrb5::spnego::accept_sec_context_header(&mut validator, &first.header)?;
        rskrb5::spnego::accept_sec_context_header(&mut validator, &second.header)?;

        let first_replay = rskrb5::spnego::accept_sec_context_header(&mut validator, &first.header)
            .expect_err("first header replay is rejected");
        let second_replay =
            rskrb5::spnego::accept_sec_context_header(&mut validator, &second.header)
                .expect_err("second header replay is rejected");

        assert!(matches!(
            first_replay,
            rskrb5::spnego::Error::Service(rskrb5::service::Error::Replay)
        ));
        assert!(matches!(
            second_replay,
            rskrb5::spnego::Error::Service(rskrb5::service::Error::Replay)
        ));

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_spnego_header_authenticates_to_docker_http() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let config = configured_kdc_config()?;
        let mut client = TokioClient::with_password(
            config,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            PASSWORD,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let header = client.spnego_header(service_principal()).await?;
        let response = http_get_with_authorization("/modgssapi/index.html", &header)?;
        let status = response.lines().next().unwrap_or_default();

        assert!(
            status.contains(" 200 "),
            "unexpected Docker HTTP response status: {status}"
        );

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_raw_krb5_header_authenticates_to_docker_http() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let mut client = TokioClient::with_password(
            configured_kdc_config()?,
            KdcProtocol::Auto,
            Principal::user(REALM, USER),
            PASSWORD,
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let service_ticket = client.get_service_ticket(service_principal()).await?;
        let context = rskrb5::spnego::init_sec_context(
            &service_ticket,
            rskrb5::spnego::InitiatorContextOptions::new(),
        )?;
        let header = format!("Negotiate {}", base64_encode(&context.krb5_token.encode()?));
        let response = http_get_with_authorization("/modgssapi/index.html", &header)?;
        let status = response.lines().next().unwrap_or_default();

        assert!(
            status.contains(" 200 "),
            "unexpected Docker HTTP response status: {status}"
        );

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_rc4_hmac_spnego_header_round_trip_through_service_validator()
-> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC RC4-HMAC SPNEGO client header round-trip over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 17, vec![RC4_HMAC_ETYPE])?,
                )
                .await?;
            assert_eq!(tgt.session_key.etype, RC4_HMAC_ETYPE);

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, 18, vec![RC4_HMAC_ETYPE])?,
            )?;
            let service_ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;
            assert_eq!(service_ticket.session_key.etype, RC4_HMAC_ETYPE);

            let context = rskrb5::spnego::init_sec_context(
                &service_ticket,
                rskrb5::spnego::InitiatorContextOptions::new(),
            )?;
            assert_eq!(context.service, service);
            assert!(context.sequence_number.is_some());

            let keytab = http_keytab()?;
            let mut validator =
                rskrb5::service::ServiceValidator::new(&keytab).with_now(SystemTime::now());
            let accepted =
                rskrb5::spnego::accept_sec_context_header(&mut validator, &context.header)?;
            assert_eq!(
                accepted.ap_req.client,
                rskrb5::service::Principal {
                    realm: REALM.to_owned(),
                    name_type: 1,
                    components: vec![USER.to_owned()],
                }
            );
            assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
            assert_eq!(accepted.ap_req.session_key.etype, RC4_HMAC_ETYPE);

            let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let response_header = accepted.ap_rep_response_header_with_confounder(
                &rc4_confounder(protocol, elapsed),
                rskrb5::service::ApRepOptions::default(),
            )?;
            let verified = context.verify_ap_rep_response_header(&response_header)?;
            assert_eq!(verified.ctime, context.authenticator_ctime);
            assert_eq!(verified.cusec, context.authenticator_cusec);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "spnego")]
#[test]
fn docker_mit_kdc_des3_spnego_header_round_trip_through_service_validator()
-> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }
    let _guard = INTEGRATION_LOCK.lock().expect("integration test lock");

    runtime().block_on(async {
        let addr = kdc_addr();
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC DES3 SPNEGO client header round-trip over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, 22, vec![DES3_ETYPE])?,
                )
                .await?;
            assert_eq!(tgt.session_key.etype, DES3_ETYPE);

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, 23, vec![DES3_ETYPE])?,
            )?;
            let service_ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;
            assert_eq!(service_ticket.session_key.etype, DES3_ETYPE);

            let context = rskrb5::spnego::init_sec_context(
                &service_ticket,
                rskrb5::spnego::InitiatorContextOptions::new(),
            )?;
            assert_eq!(context.service, service);
            assert!(context.sequence_number.is_some());

            let keytab = http_keytab()?;
            let mut validator =
                rskrb5::service::ServiceValidator::new(&keytab).with_now(SystemTime::now());
            let accepted =
                rskrb5::spnego::accept_sec_context_header(&mut validator, &context.header)?;
            assert_eq!(
                accepted.ap_req.client,
                rskrb5::service::Principal {
                    realm: REALM.to_owned(),
                    name_type: 1,
                    components: vec![USER.to_owned()],
                }
            );
            assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
            assert_eq!(accepted.ap_req.session_key.etype, DES3_ETYPE);

            let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let response_header = accepted.ap_rep_response_header_with_confounder(
                &des3_confounder(protocol, elapsed),
                rskrb5::service::ApRepOptions::default(),
            )?;
            let verified = context.verify_ap_rep_response_header(&response_header)?;
            assert_eq!(verified.ctime, context.authenticator_ctime);
            assert_eq!(verified.cusec, context.authenticator_cusec);
        }

        Ok::<_, Box<dyn Error>>(())
    })
}

fn build_login_request(
    protocol: KdcProtocol,
    key: EncryptionKey,
) -> Result<rskrb5::client::BuiltAsReq, Box<dyn Error>> {
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let timestamp = UNIX_EPOCH + Duration::from_secs(elapsed.as_secs());
    let cusec = match protocol {
        KdcProtocol::Udp => elapsed.subsec_micros(),
        KdcProtocol::Tcp => (elapsed.subsec_micros() + 1) % 1_000_000,
        KdcProtocol::Auto => (elapsed.subsec_micros() + 2) % 1_000_000,
    };
    let nonce = ((elapsed.as_nanos() as u32) & 0x0fff_ffff)
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
            KdcProtocol::Auto => 0x3000_0000,
        };
    let padata = pa_enc_timestamp_with_confounder(
        &key,
        timestamp,
        cusec,
        &confounder(protocol, elapsed),
        Some(TESTUSER1_KVNO),
    )?;
    let options = AsReqOptions::new(timestamp, nonce)
        .with_ticket_lifetime(Duration::from_secs(24 * 60 * 60))
        .with_etypes(vec![AES256_ETYPE])
        .with_padata(vec![padata]);

    Ok(build_tgt_as_req(Principal::user(REALM, USER), options)?)
}

fn login_options(protocol: KdcProtocol, sequence: u32) -> Result<AsReqOptions, Box<dyn Error>> {
    login_options_with_etypes(protocol, sequence, vec![AES256_ETYPE])
}

fn login_options_with_etypes(
    protocol: KdcProtocol,
    sequence: u32,
    etypes: Vec<i32>,
) -> Result<AsReqOptions, Box<dyn Error>> {
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let nonce = (((elapsed.as_nanos() as u32) & 0x00ff_ffff) | (sequence << 24))
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
            KdcProtocol::Auto => 0x3000_0000,
        };
    Ok(AsReqOptions::new(now, nonce)
        .with_ticket_lifetime(Duration::from_secs(24 * 60 * 60))
        .with_etypes(etypes))
}

fn tgs_options(protocol: KdcProtocol, sequence: u32) -> Result<TgsReqOptions, Box<dyn Error>> {
    tgs_options_with_etypes(protocol, sequence, vec![AES256_ETYPE])
}

fn tgs_options_with_etypes(
    protocol: KdcProtocol,
    sequence: u32,
    etypes: Vec<i32>,
) -> Result<TgsReqOptions, Box<dyn Error>> {
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let nonce = (((elapsed.as_nanos() as u32) & 0x00ff_ffff) | (sequence << 24))
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
            KdcProtocol::Auto => 0x3000_0000,
        };
    Ok(TgsReqOptions::new(now, nonce)
        .with_ticket_lifetime(Duration::from_secs(24 * 60 * 60))
        .with_etypes(etypes))
}

fn service_principal() -> Principal {
    Principal::new(REALM, 2, ["HTTP", SERVICE_HOST])
}

fn resdom_service_principal() -> Principal {
    Principal::new(RESDOM_REALM, 2, ["HTTP", RESDOM_SERVICE_HOST])
}

#[cfg(feature = "spnego")]
fn http_get_with_authorization(path: &str, authorization: &str) -> Result<String, Box<dyn Error>> {
    let target = http_target(path)?;
    let mut stream = TcpStream::connect(&target.addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
        target.path, target.authority, authorization
    )?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(feature = "spnego")]
struct HttpTarget {
    authority: String,
    addr: String,
    path: String,
}

#[cfg(feature = "spnego")]
fn http_target(path: &str) -> Result<HttpTarget, Box<dyn Error>> {
    let base = std::env::var("TEST_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1".to_owned());
    let Some(without_scheme) = base.strip_prefix("http://") else {
        return Err(format!("TEST_HTTP_URL must be an http:// URL: {base}").into());
    };
    let (authority, base_path) = without_scheme
        .split_once('/')
        .map_or((without_scheme, ""), |(authority, path)| (authority, path));
    if authority.is_empty() {
        return Err("TEST_HTTP_URL must include a host".into());
    }

    let port = if authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        authority
            .rsplit_once(':')
            .expect("port checked")
            .1
            .to_owned()
    } else {
        "80".to_owned()
    };
    let connect_host = std::env::var("TEST_HTTP_ADDR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| authority.to_owned());
    let addr = if connect_host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        connect_host
    } else {
        format!("{connect_host}:{port}")
    };
    let base_path = base_path.trim_matches('/');
    let request_path = ensure_absolute_path(path);
    let path = if base_path.is_empty() {
        request_path
    } else {
        format!("/{base_path}{request_path}")
    };

    Ok(HttpTarget {
        authority: authority.to_owned(),
        addr,
        path,
    })
}

#[cfg(feature = "spnego")]
fn ensure_absolute_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

async fn assert_keytab_as_tgs_for_etypes(
    addr: &str,
    etypes: &[i32],
    mut sequence: u32,
) -> Result<(), Box<dyn Error>> {
    let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
    let keytab = testuser_keytab_for_etypes(etypes)?;

    for etype in etypes {
        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC keytab etype {etype} AS/TGS exchange over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_keytab(
                    protocol,
                    addr,
                    Principal::user(REALM, USER),
                    &keytab,
                    login_options_with_etypes(protocol, sequence, vec![*etype])?,
                )
                .await?;
            sequence += 1;
            assert_eq!(tgt.session_key.etype, *etype);
            assert!(!tgt.session_key.value.is_empty());

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, sequence, vec![*etype])?,
            )?;
            sequence += 1;
            let ticket = transport
                .exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, *etype);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }
    }

    Ok(())
}

async fn assert_password_as_tgs_for_etypes(
    addr: &str,
    etypes: &[i32],
    mut sequence: u32,
) -> Result<(), Box<dyn Error>> {
    let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

    for etype in etypes {
        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            eprintln!(
                "running Docker KDC password etype {etype} AS/TGS exchange over {protocol:?} to {addr}"
            );
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr,
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options_with_etypes(protocol, sequence, vec![*etype])?,
                )
                .await?;
            sequence += 1;
            assert_eq!(tgt.session_key.etype, *etype);
            assert!(!tgt.session_key.value.is_empty());

            let service = service_principal();
            let request = build_tgs_req(
                &tgt,
                service.clone(),
                tgs_options_with_etypes(protocol, sequence, vec![*etype])?,
            )?;
            sequence += 1;
            let ticket = transport
                .exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, *etype);
            assert!(!ticket.session_key.value.is_empty());
            assert!(!ticket.ticket.is_empty());
            assert!(ticket.end_time > ticket.start_time);
        }
    }

    Ok(())
}

async fn change_password_once(
    config: &Config,
    protocol: KdcProtocol,
    current_password: &[u8],
    new_password: &[u8],
) -> Result<rskrb5::kadmin::ChangePasswordResult, Box<dyn Error>> {
    let mut client = TokioClient::with_password(
        config.clone(),
        protocol,
        Principal::user(REALM, USER),
        current_password.to_vec(),
    )
    .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

    Ok(client
        .change_password(new_password, kpasswd_sender_address()?)
        .await?)
}

async fn password_login(
    config: &Config,
    protocol: KdcProtocol,
    password: &[u8],
) -> Result<rskrb5::client::AsRepSession, Box<dyn Error>> {
    let mut client = TokioClient::with_password(
        config.clone(),
        protocol,
        Principal::user(REALM, USER),
        password.to_vec(),
    )
    .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

    Ok(client.login().await?.clone())
}

fn kpasswd_sender_address() -> Result<rasn_kerberos::HostAddress, Box<dyn Error>> {
    let address = match std::env::var("TEST_KPASSWD_SADDR") {
        Ok(value) => value.parse::<Ipv4Addr>()?,
        Err(std::env::VarError::NotPresent) => Ipv4Addr::new(127, 0, 0, 1),
        Err(error) => return Err(error.into()),
    };
    Ok(ipv4_host_address(address.octets()))
}

fn testuser_reply_key() -> Result<EncryptionKey, Box<dyn Error>> {
    let etype = AesSha1Etype::Aes256;
    Ok(EncryptionKey {
        etype: etype.etype_id(),
        value: etype.string_to_key(PASSWORD, TESTUSER1_SALT, etype.default_s2kparams())?,
    })
}

fn testuser_keytab() -> Result<Keytab, Box<dyn Error>> {
    testuser_keytab_for_etypes(&[AES256_ETYPE])
}

fn keytab_from_hex(hex: &str) -> Result<Keytab, Box<dyn Error>> {
    Ok(Keytab::parse(&decode_hex(hex))?)
}

fn testuser_keytab_for_etypes(etypes: &[i32]) -> Result<Keytab, Box<dyn Error>> {
    let mut keytab = Keytab::new();
    for etype in etypes {
        keytab.entries_mut().push(testuser_keytab_entry(*etype)?);
    }
    Ok(keytab)
}

fn testuser_keytab_entry(etype: i32) -> Result<KeytabEntry, Box<dyn Error>> {
    Ok(KeytabEntry {
        principal: KeytabPrincipal {
            realm: REALM.to_owned(),
            components: vec![USER.to_owned()],
            name_type: 1,
        },
        timestamp: 1_893_553_440,
        kvno8: TESTUSER1_KVNO as u8,
        key: derive_password_reply_key(
            &Principal::user(REALM, USER),
            PASSWORD,
            &PreauthKeyInfo {
                etype,
                salt: Some(String::from_utf8(TESTUSER1_SALT.to_vec())?),
                s2kparams: testuser_s2kparams(etype),
            },
        )?,
        kvno: TESTUSER1_KVNO,
    })
}

fn testuser_s2kparams(etype: i32) -> Option<Vec<u8>> {
    match etype {
        AES128_ETYPE | AES256_ETYPE => Some(vec![0, 0, 16, 0]),
        AES128_SHA2_ETYPE | AES256_SHA2_ETYPE => Some(vec![0, 0, 128, 0]),
        _ => None,
    }
}

fn assert_login_session(session: rskrb5::client::AsRepSession) {
    assert_eq!(session.client, Principal::user(REALM, USER));
    assert_eq!(session.service, Principal::tgt_service(REALM));
    assert_eq!(session.session_key.etype, AES256_ETYPE);
    assert!(!session.session_key.value.is_empty());
    assert!(!session.ticket.is_empty());
    assert!(session.end_time > session.start_time);
}

fn confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 16] {
    let mut confounder = [0; 16];
    confounder[0] = match protocol {
        KdcProtocol::Udp => 1,
        KdcProtocol::Tcp => 2,
        KdcProtocol::Auto => 3,
    };
    confounder[1..9].copy_from_slice(&elapsed.as_secs().to_be_bytes());
    confounder[9..13].copy_from_slice(&elapsed.subsec_nanos().to_be_bytes());
    confounder
}

#[cfg(feature = "spnego")]
fn rc4_confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 8] {
    let mut confounder = [0; 8];
    confounder[0] = match protocol {
        KdcProtocol::Udp => 1,
        KdcProtocol::Tcp => 2,
        KdcProtocol::Auto => 3,
    };
    confounder[1..5].copy_from_slice(&elapsed.subsec_nanos().to_be_bytes());
    confounder[5..8].copy_from_slice(&elapsed.as_secs().to_be_bytes()[5..8]);
    confounder
}

#[cfg(feature = "spnego")]
fn des3_confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 8] {
    let mut confounder = [0; 8];
    confounder[0] = match protocol {
        KdcProtocol::Udp => 3,
        KdcProtocol::Tcp => 4,
        KdcProtocol::Auto => 5,
    };
    confounder[1..5].copy_from_slice(&elapsed.subsec_nanos().to_be_bytes());
    confounder[5..8].copy_from_slice(&elapsed.as_secs().to_be_bytes()[5..8]);
    confounder
}

struct ExternalKrbEnv {
    config_path: PathBuf,
    ccache_path: PathBuf,
    ccache_name: String,
}

impl ExternalKrbEnv {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let config_path = temp_integration_file(&format!("{label}-krb5.conf"))?;
        let ccache_path = temp_integration_file(&format!("{label}-ccache"))?;
        let ccache_name = format!("FILE:{}", ccache_path.display());
        fs::write(&config_path, external_tool_krb5_conf())?;
        Ok(Self {
            config_path,
            ccache_path,
            ccache_name,
        })
    }

    fn kinit(&self) -> Result<(), Box<dyn Error>> {
        let mut child = self
            .command("kinit")
            .arg(format!("{USER}@{REALM}"))
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("kinit stdin is piped");
        stdin.write_all(PASSWORD)?;
        stdin.write_all(b"\n")?;
        drop(stdin);
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "kinit failed with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn kvno(&self, service: &str) -> Result<(), Box<dyn Error>> {
        let output = self.command("kvno").arg(service).output()?;
        if !output.status.success() {
            return Err(format!(
                "kvno failed with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .env("KRB5_CONFIG", &self.config_path)
            .env("KRB5CCNAME", &self.ccache_name);
        command
    }
}

impl Drop for ExternalKrbEnv {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.config_path);
        let _ = fs::remove_file(&self.ccache_path);
    }
}

fn privileged_integration_enabled() -> bool {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return false;
    }
    if std::env::var("TESTPRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping privileged Docker KDC integration test; set TESTPRIVILEGED=1 to enable"
        );
        return false;
    }
    if !command_available("kinit") {
        eprintln!(
            "skipping privileged Docker KDC integration test; set a PATH-accessible kinit binary to enable"
        );
        return false;
    }
    true
}

fn privileged_kvno_integration_enabled() -> bool {
    if !privileged_integration_enabled() {
        return false;
    }
    if !command_available("kvno") {
        eprintln!(
            "skipping privileged Docker KDC kvno tests; set a PATH-accessible kvno binary to enable"
        );
        return false;
    }
    true
}

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn external_tool_krb5_conf() -> String {
    format!(
        r#"
[libdefaults]
 default_realm = {REALM}
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = yes
 default_tkt_enctypes = aes256-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96
 noaddresses = false

[realms]
 {REALM} = {{
  kdc = {}
  default_domain = test.gokrb5
 }}

[domain_realm]
 .test.gokrb5 = {REALM}
 test.gokrb5 = {REALM}
"#,
        kdc_addr()
    )
}

fn temp_integration_file(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(std::env::temp_dir().join(format!(
        "rskrb5-{name}-{}-{}",
        std::process::id(),
        elapsed.as_nanos()
    )))
}

fn kdc_addr() -> String {
    let host = std::env::var("TEST_KDC_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_KDC_PORT").unwrap_or_else(|_| "88".to_owned());
    format!("{host}:{port}")
}

fn closed_tcp_kdc_addr() -> String {
    std::env::var("TEST_BAD_KDC_ADDR").unwrap_or_else(|_| "127.0.0.1:9".to_owned())
}

fn short_kdc_addr() -> String {
    let host = std::env::var("TEST_SHORT_KDC_ADDR")
        .or_else(|_| std::env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_SHORT_KDC_PORT").unwrap_or_else(|_| "58".to_owned());
    format!("{host}:{port}")
}

fn old_kdc_addr() -> String {
    let host = std::env::var("TEST_OLD_KDC_ADDR")
        .or_else(|_| std::env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_OLD_KDC_PORT").unwrap_or_else(|_| "78".to_owned());
    format!("{host}:{port}")
}

fn latest_kdc_addr() -> String {
    let host = std::env::var("TEST_LATEST_KDC_ADDR")
        .or_else(|_| std::env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_LATEST_KDC_PORT").unwrap_or_else(|_| "98".to_owned());
    format!("{host}:{port}")
}

fn configured_kdc_config() -> Result<Config, Box<dyn Error>> {
    configured_kdc_config_with_primary_realm_kdcs(&[kdc_addr()])
}

fn configured_kdc_config_with_primary_realm_kdcs(
    kdcs: &[String],
) -> Result<Config, Box<dyn Error>> {
    let primary_kdcs = kdcs
        .iter()
        .map(|kdc| format!("  kdc = {kdc}\n"))
        .collect::<String>();

    Ok(Config::parse(&format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 {REALM} = {{
{primary_kdcs}
 }}
 {RESDOM_REALM} = {{
  kdc = {}
 }}

[domain_realm]
 .test.gokrb5 = {REALM}
 test.gokrb5 = {REALM}
 .resdom.gokrb5 = {RESDOM_REALM}
 resdom.gokrb5 = {RESDOM_REALM}
"#,
        resdom_kdc_addr()
    ))?)
}

fn short_kdc_config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 renew_lifetime = 600

[realms]
 {REALM} = {{
  kdc = {}
 }}
"#,
        short_kdc_addr()
    ))?)
}

fn configured_kpasswd_config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 {REALM} = {{
  kdc = {}
  kpasswd_server = {}
 }}
"#,
        kdc_addr(),
        kpasswd_addr()
    ))?)
}

fn resdom_kdc_addr() -> String {
    let host = std::env::var("TEST_RESDOM_KDC_ADDR")
        .or_else(|_| std::env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_RESDOM_KDC_PORT").unwrap_or_else(|_| "188".to_owned());
    format!("{host}:{port}")
}

fn kpasswd_addr() -> String {
    let host = std::env::var("TEST_KPASSWD_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = std::env::var("TEST_KPASSWD_PORT").unwrap_or_else(|_| "464".to_owned());
    format!("{host}:{port}")
}

fn dns_kdc_config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        r#"
[libdefaults]
 dns_lookup_kdc = true
 default_realm = {REALM}
"#
    ))?)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

#[cfg(feature = "spnego")]
fn http_keytab() -> Result<Keytab, Box<dyn Error>> {
    Ok(Keytab::parse(&decode_hex(HTTP_KEYTAB))?)
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

#[cfg(feature = "spnego")]
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
