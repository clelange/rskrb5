#![cfg(feature = "tokio")]

use std::error::Error;
use std::time::Duration;

use rskrb5::client::{
    Error as ClientError, KRB_ERR_RESPONSE_TOO_BIG, KdcEndpoint, KdcEndpointSource, KdcProtocol,
    TokioKdcTransport,
};
use rskrb5::config::Config;
use rskrb5::kadmin::{
    Error as KadminError, KPASSWD_AUTHERROR, KPASSWD_SUCCESS, Request as KpasswdRequest,
};
use rskrb5::keytab::EncryptionKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const MARSHALLED_KPASSWD_REQ: &str = include_str!("fixtures/kpasswd-request.hex");
const KPASSWD_HEADER_LEN: usize = 6;

#[test]
fn tokio_transport_sends_udp_datagram() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;
        let task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(&request[..len], b"udp-as-req");
            server
                .send_to(b"udp-as-rep", peer)
                .await
                .expect("send response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send(KdcProtocol::Udp, addr, b"udp-as-req")
            .await?;

        task.await?;
        assert_eq!(response, b"udp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_uses_tcp_length_prefix() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
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
            assert_eq!(request, b"tcp-as-req");

            socket
                .write_all(&(10_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_tcp(addr, b"tcp-as-req")
            .await?;

        task.await?;
        assert_eq!(response, b"tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn configured_kdc_endpoint_parses_authorities() -> Result<(), Box<dyn Error>> {
    let host = KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:88")?;
    assert_eq!(host.protocol, KdcProtocol::Tcp);
    assert_eq!(host.host, "kdc.test.gokrb5");
    assert_eq!(host.port, 88);
    assert_eq!(host.source, KdcEndpointSource::Config);
    assert_eq!(host.authority(), "kdc.test.gokrb5:88");

    let default_port = KdcEndpoint::configured(KdcProtocol::Udp, "kdc.test.gokrb5")?;
    assert_eq!(default_port.port, 88);

    let kpasswd_default_port =
        KdcEndpoint::configured_with_default_port(KdcProtocol::Tcp, "kpasswd.test.gokrb5", 464)?;
    assert_eq!(kpasswd_default_port.host, "kpasswd.test.gokrb5");
    assert_eq!(kpasswd_default_port.port, 464);

    let ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "[::1]:1088")?;
    assert_eq!(ipv6.host, "::1");
    assert_eq!(ipv6.port, 1088);
    assert_eq!(ipv6.authority(), "[::1]:1088");

    let bare_ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "::1")?;
    assert_eq!(bare_ipv6.host, "::1");
    assert_eq!(bare_ipv6.port, 88);

    assert!(KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:not-a-port").is_err());
    Ok(())
}

#[test]
fn tokio_transport_sends_udp_to_configured_realm_kdc() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;
        let config = config_with_kdcs([addr.to_string()]);
        let task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(&request[..len], b"configured-udp-as-req");
            server
                .send_to(b"configured-udp-as-rep", peer)
                .await
                .expect("send response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Udp,
                "TEST.GOKRB5",
                b"configured-udp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"configured-udp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_sends_tcp_to_configured_realm_kdc() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs([addr.to_string()]);
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
            assert_eq!(request, b"configured-tcp-as-req");

            socket
                .write_all(&(21_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"configured-tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                b"configured-tcp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"configured-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_discovers_configured_kpasswd_servers() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let config = config_with_kpasswd_servers(
            ["kpasswd.test.gokrb5".to_owned(), "[::1]:7464".to_owned()],
            1465,
        );

        let endpoints = TokioKdcTransport::new()
            .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
            .await?;

        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].protocol, KdcProtocol::Tcp);
        assert_eq!(endpoints[0].host, "kpasswd.test.gokrb5");
        assert_eq!(endpoints[0].port, 464);
        assert_eq!(endpoints[0].source, KdcEndpointSource::Config);
        assert_eq!(endpoints[1].host, "::1");
        assert_eq!(endpoints[1].port, 7464);
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_sends_tcp_to_configured_kpasswd_server() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"kpasswd-tcp-req");
            write_tcp_response(&mut socket, b"kpasswd-tcp-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_kpasswd_realm(&config, KdcProtocol::Tcp, "TEST.GOKRB5", b"kpasswd-tcp-req")
            .await?;

        task.await?;
        assert_eq!(response, b"kpasswd-tcp-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_exchanges_configured_kpasswd_request() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(0, &response_too_big_error());
        let expected_response_len = response.len();
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, expected_request);
            write_tcp_response(&mut socket, &response).await;
        });

        let reply = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_request_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
            )
            .await?;

        task.await?;
        assert!(reply.is_krb_error());
        assert_eq!(reply.message_length as usize, expected_response_len);
        assert_eq!(
            reply.krb_error.expect("KRB-ERROR parsed").error_code,
            KRB_ERR_RESPONSE_TOO_BIG
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_exchanges_configured_kpasswd_success_result() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed"),
        );
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, expected_request);
            write_tcp_response(&mut socket, &response).await;
        });

        let result = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_result_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
                &reply_key(),
            )
            .await?;

        task.await?;
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_exchanges_configured_kpasswd_failure_result() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_AUTHERROR, "authentication failed"),
        );
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, expected_request);
            write_tcp_response(&mut socket, &response).await;
        });

        let error = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_result_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
                &reply_key(),
            )
            .await
            .expect_err("non-zero kpasswd result returns error");

        task.await?;
        assert!(matches!(
            error,
            ClientError::Kadmin(KadminError::PasswordChangeFailed { code, text })
                if code == KPASSWD_AUTHERROR && text == "authentication failed"
        ));
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_tries_next_configured_kdc_after_tcp_failure() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs(["127.0.0.1:9".to_owned(), addr.to_string()]);
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
            assert_eq!(request, b"fallback-tcp-as-req");

            socket
                .write_all(&(19_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"fallback-tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                b"fallback-tcp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"fallback-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_auto_retries_tcp_after_udp_response_too_big() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = udp.local_addr()?;
        let listener = TcpListener::bind(addr).await?;

        let udp_task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = udp.recv_from(&mut request).await.expect("receive UDP");
            assert_eq!(&request[..len], b"auto-as-req");
            udp.send_to(&response_too_big_error(), peer)
                .await
                .expect("send UDP KRB-ERROR");
        });
        let tcp_task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-as-req");
            write_tcp_response(&mut socket, b"auto-tcp-as-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send(KdcProtocol::Auto, addr, b"auto-as-req")
            .await?;

        udp_task.await?;
        tcp_task.await?;
        assert_eq!(response, b"auto-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_auto_honors_tcp_only_udp_preference_limit() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs_and_udp_limit([addr.to_string()], 1);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-config-as-req");
            write_tcp_response(&mut socket, b"auto-config-tcp-as-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Auto,
                "TEST.GOKRB5",
                b"auto-config-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"auto-config-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn tokio_transport_auto_kpasswd_honors_tcp_only_udp_preference_limit() -> Result<(), Box<dyn Error>>
{
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-kpasswd-req");
            write_tcp_response(&mut socket, b"auto-kpasswd-tcp-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_kpasswd_realm(
                &config,
                KdcProtocol::Auto,
                "TEST.GOKRB5",
                b"auto-kpasswd-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"auto-kpasswd-tcp-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

fn config_with_kdcs<I>(kdcs: I) -> Config
where
    I: IntoIterator<Item = String>,
{
    config_with_kdcs_and_udp_limit(kdcs, 1465)
}

fn config_with_kdcs_and_udp_limit<I>(kdcs: I, udp_preference_limit: i32) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut input = String::from(
        r#"
[libdefaults]
 dns_lookup_kdc = false
"#,
    );
    input.push_str(" udp_preference_limit = ");
    input.push_str(&udp_preference_limit.to_string());
    input.push_str(
        r#"

[realms]
 TEST.GOKRB5 = {
"#,
    );
    for kdc in kdcs {
        input.push_str("  kdc = ");
        input.push_str(&kdc);
        input.push('\n');
    }
    input.push_str(" }\n");
    Config::parse(&input).expect("config parses")
}

fn config_with_kpasswd_servers<I>(servers: I, udp_preference_limit: i32) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut input = String::from(
        r#"
[libdefaults]
 dns_lookup_kdc = false
"#,
    );
    input.push_str(" udp_preference_limit = ");
    input.push_str(&udp_preference_limit.to_string());
    input.push_str(
        r#"

[realms]
 TEST.GOKRB5 = {
"#,
    );
    for server in servers {
        input.push_str("  kpasswd_server = ");
        input.push_str(&server);
        input.push('\n');
    }
    input.push_str(" }\n");
    Config::parse(&input).expect("config parses")
}

async fn read_tcp_request(listener: &TcpListener) -> (Vec<u8>, tokio::net::TcpStream) {
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

async fn write_tcp_response(socket: &mut tokio::net::TcpStream, response: &[u8]) {
    socket
        .write_all(&(response.len() as u32).to_be_bytes())
        .await
        .expect("write response length");
    socket.write_all(response).await.expect("write response");
}

fn response_too_big_error() -> Vec<u8> {
    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: KRB_ERR_RESPONSE_TOO_BIG,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&["krbtgt", "TEST.GOKRB5"]),
        e_text: Some(kerberos_string("response too big")),
        e_data: None,
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

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
        error_code: KRB_ERR_RESPONSE_TOO_BIG,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&["kadmin", "changepw"]),
        e_text: Some(kerberos_string(text)),
        e_data: Some(e_data.into()),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: vec![0; 32],
    }
}

fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Vec<u8> {
    let message_length = KPASSWD_HEADER_LEN + body.len();
    assert!(u16::try_from(message_length).is_ok());

    let mut frame = Vec::with_capacity(message_length);
    frame.extend_from_slice(&(message_length as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&ap_rep_length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0]);
            let lo = hex_nibble(pair[1]);
            (hi << 4) | lo
        })
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit: {value}"),
    }
}

fn kerberos_time(seconds: i64) -> rasn_kerberos::KerberosTime {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0).expect("valid time");
    let offset = chrono::FixedOffset::east_opt(0).expect("UTC offset exists");
    rasn_kerberos::KerberosTime(utc.with_timezone(&offset))
}

fn rasn_principal(components: &[&str]) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: 2,
        string: components
            .iter()
            .map(|component| kerberos_string(component))
            .collect(),
    }
}

fn realm(value: &str) -> rasn_kerberos::Realm {
    kerberos_string(value)
}

fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::try_from(value).expect("valid KerberosString")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}
