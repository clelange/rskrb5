#![cfg(feature = "tokio")]

use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rskrb5::client::{
    AsReqOptions, KdcProtocol, Principal, TokioKdcTransport, build_tgt_as_req,
    pa_enc_timestamp_with_confounder,
};
use rskrb5::crypto::AesSha1Etype;
use rskrb5::keytab::EncryptionKey;

const REALM: &str = "TEST.GOKRB5";
const USER: &str = "testuser1";
const PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER1_SALT: &[u8] = b"TEST.GOKRB5testuser1";
const AES256_ETYPE: i32 = 18;
const TESTUSER1_KVNO: u32 = 2;

#[test]
fn docker_mit_kdc_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    if std::env::var("INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipping Docker KDC integration test; set INTEGRATION=1 to enable");
        return Ok(());
    }

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

fn testuser_reply_key() -> Result<EncryptionKey, Box<dyn Error>> {
    let etype = AesSha1Etype::Aes256;
    Ok(EncryptionKey {
        etype: etype.etype_id(),
        value: etype.string_to_key(PASSWORD, TESTUSER1_SALT, etype.default_s2kparams())?,
    })
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
