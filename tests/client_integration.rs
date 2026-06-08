#![cfg(feature = "tokio")]

use std::error::Error;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rskrb5::client::{
    AsReqOptions, KdcProtocol, PreauthKeyInfo, Principal, TgsReqOptions, TokioKdcTransport,
    build_tgs_req, build_tgt_as_req, derive_password_reply_key, pa_enc_timestamp_with_confounder,
};
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}
