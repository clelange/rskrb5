#![cfg(feature = "tokio")]

use std::error::Error;
use std::time::Duration;

use rskrb5::client::{KdcEndpoint, KdcEndpointSource, KdcProtocol, TokioKdcTransport};
use rskrb5::config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

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

fn config_with_kdcs<I>(kdcs: I) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut input = String::from(
        r#"
[libdefaults]
 dns_lookup_kdc = false

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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}
