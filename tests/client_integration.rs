#![cfg(feature = "tokio")]

use std::error::Error;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rskrb5::client::{
    AsReqOptions, KdcProtocol, PreauthKeyInfo, Principal, TgsReqOptions, TokioKdcTransport,
    build_tgs_req, build_tgt_as_req, derive_password_reply_key, pa_enc_timestamp_with_confounder,
};
use rskrb5::config::Config;
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};

const REALM: &str = "TEST.GOKRB5";
const USER: &str = "testuser1";
const PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER1_SALT: &[u8] = b"TEST.GOKRB5testuser1";
const AES256_ETYPE: i32 = 18;
const TESTUSER1_KVNO: u32 = 2;
const SERVICE_HOST: &str = "host.test.gokrb5";
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
    };
    let nonce = ((elapsed.as_nanos() as u32) & 0x0fff_ffff)
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
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
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let nonce = (((elapsed.as_nanos() as u32) & 0x00ff_ffff) | (sequence << 24))
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
        };
    Ok(AsReqOptions::new(now, nonce)
        .with_ticket_lifetime(Duration::from_secs(24 * 60 * 60))
        .with_etypes(vec![AES256_ETYPE]))
}

fn tgs_options(protocol: KdcProtocol, sequence: u32) -> Result<TgsReqOptions, Box<dyn Error>> {
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let nonce = (((elapsed.as_nanos() as u32) & 0x00ff_ffff) | (sequence << 24))
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
        };
    Ok(TgsReqOptions::new(now, nonce)
        .with_ticket_lifetime(Duration::from_secs(24 * 60 * 60))
        .with_etypes(vec![AES256_ETYPE]))
}

fn service_principal() -> Principal {
    Principal::new(REALM, 2, ["HTTP", SERVICE_HOST])
}

fn testuser_reply_key() -> Result<EncryptionKey, Box<dyn Error>> {
    let etype = AesSha1Etype::Aes256;
    Ok(EncryptionKey {
        etype: etype.etype_id(),
        value: etype.string_to_key(PASSWORD, TESTUSER1_SALT, etype.default_s2kparams())?,
    })
}

fn testuser_keytab() -> Result<Keytab, Box<dyn Error>> {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(KeytabEntry {
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
                etype: AES256_ETYPE,
                salt: Some(String::from_utf8(TESTUSER1_SALT.to_vec())?),
                s2kparams: Some(vec![0, 0, 16, 0]),
            },
        )?,
        kvno: TESTUSER1_KVNO,
    });
    Ok(keytab)
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
    };
    confounder[1..9].copy_from_slice(&elapsed.as_secs().to_be_bytes());
    confounder[9..13].copy_from_slice(&elapsed.subsec_nanos().to_be_bytes());
    confounder
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

fn configured_kdc_config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 {REALM} = {{
  kdc = {}
 }}
"#,
        kdc_addr()
    ))?)
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

#[cfg(feature = "spnego")]
fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

#[cfg(feature = "spnego")]
fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
