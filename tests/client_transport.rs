#![cfg(feature = "tokio")]

use std::error::Error;
use std::time::Duration;

use rskrb5::client::{KdcProtocol, TokioKdcTransport};
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}
