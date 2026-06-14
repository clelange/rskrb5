//! Tokio-backed KDC transport, endpoint discovery, and network exchanges.

use std::future::Future;
use std::time::Duration;

use crate::config::Config;
use crate::keytab::{EncryptionKey, Keytab};
use hickory_resolver::{TokioResolver, proto::rr::RData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};

use super::{
    AsRepSession, AsReqOptions, BuiltAsReq, BuiltTgsReq, Error, KRB_ERR_RESPONSE_TOO_BIG,
    KRB_NT_SRV_INST, Principal, ReferralTgsResult, TgsRepSession, TgsReqOptions,
    build_s4u2proxy_req, build_s4u2self_req, build_tgs_req_for_realm, build_tgt_renewal_req,
    build_ticket_renewal_req, keytab_initial_as_rep_session, keytab_initial_as_req,
    keytab_preauth_request, password_initial_as_rep_session, password_initial_as_req,
    password_preauth_request, principal_matches, process_as_rep, process_tgs_rep,
    process_tgs_rep_with_referral, service_realm, tgt_realm,
};

#[cfg(feature = "tokio")]
const DEFAULT_KDC_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "tokio")]
const DEFAULT_TCP_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
#[cfg(feature = "tokio")]
const MAX_UDP_DATAGRAM: usize = 65_507;
#[cfg(feature = "tokio")]
const DEFAULT_MAX_REFERRALS: usize = 5;

/// KDC wire protocol for Tokio transport operations.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KdcProtocol {
    /// RFC 4120 UDP transport with raw DER request and response datagrams.
    Udp,
    /// RFC 4120 TCP transport with a four-byte big-endian length prefix.
    Tcp,
    /// gokrb5-style transport preference using UDP/TCP fallback.
    Auto,
}

/// Source used to discover a KDC endpoint.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KdcEndpointSource {
    /// Endpoint came from a `[realms]` `kdc = ...` entry.
    Config,
    /// Endpoint came from `_kerberos._udp` or `_kerberos._tcp` DNS SRV lookup.
    DnsSrv,
}

/// One KDC endpoint discovered for a realm.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KdcEndpoint {
    /// Wire protocol to use for this endpoint.
    pub protocol: KdcProtocol,
    /// Host name or IP literal.
    pub host: String,
    /// Kerberos service port.
    pub port: u16,
    /// How this endpoint was discovered.
    pub source: KdcEndpointSource,
}

#[cfg(feature = "tokio")]
impl KdcEndpoint {
    /// Create a configured endpoint from a `host[:port]` value.
    pub fn configured(protocol: KdcProtocol, value: &str) -> Result<Self, Error> {
        Self::configured_with_default_port(protocol, value, 88)
    }

    /// Create a configured endpoint from a `host[:port]` value and default port.
    pub fn configured_with_default_port(
        protocol: KdcProtocol,
        value: &str,
        default_port: u16,
    ) -> Result<Self, Error> {
        let (host, port) = parse_kdc_endpoint(value, default_port)?;
        Ok(Self {
            protocol,
            host,
            port,
            source: KdcEndpointSource::Config,
        })
    }

    /// Return a display-friendly `host:port` authority.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Tokio-backed KDC transport for explicit TCP or UDP exchanges.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokioKdcTransport {
    timeout: Duration,
    udp_response_limit: usize,
    tcp_response_limit: usize,
}

#[cfg(feature = "tokio")]
impl Default for TokioKdcTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
impl TokioKdcTransport {
    /// Create a transport with conservative gokrb5-compatible defaults.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_KDC_TIMEOUT,
            udp_response_limit: MAX_UDP_DATAGRAM + 1,
            tcp_response_limit: DEFAULT_TCP_RESPONSE_LIMIT,
        }
    }

    /// Override the timeout applied to each KDC exchange.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the UDP receive buffer size.
    pub fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self {
        self.udp_response_limit = udp_response_limit;
        self
    }

    /// Override the maximum accepted TCP response body size.
    pub fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self {
        self.tcp_response_limit = tcp_response_limit;
        self
    }

    /// Send an encoded KDC request over UDP.
    pub async fn send_udp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        if request.len() > MAX_UDP_DATAGRAM {
            return Err(Error::UdpRequestTooLarge {
                actual: request.len(),
                limit: MAX_UDP_DATAGRAM,
            });
        }

        self.with_transport_timeout(async {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(addr).await?;
            socket.send(request).await?;

            let mut response = vec![0; self.udp_response_limit];
            let len = socket.recv(&mut response).await?;
            response.truncate(len);
            Ok(response)
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over RFC 4120 TCP framing.
    pub async fn send_tcp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        let request_len = request
            .len()
            .try_into()
            .map_err(|_| Error::TcpRequestTooLarge {
                actual: request.len(),
            })?;

        self.with_transport_timeout(async {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&u32::to_be_bytes(request_len)).await?;
            stream.write_all(request).await?;

            let mut header = [0; 4];
            stream.read_exact(&mut header).await?;
            let response_len = u32::from_be_bytes(header);
            let response_len_usize = response_len as usize;
            if response_len_usize > self.tcp_response_limit {
                return Err(Error::TcpResponseTooLarge {
                    actual: response_len,
                    limit: self.tcp_response_limit,
                });
            }

            let mut response = vec![0; response_len_usize];
            stream.read_exact(&mut response).await?;
            Ok(response)
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over the selected protocol.
    pub async fn send<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Udp => self.send_udp(addr, request).await,
            KdcProtocol::Tcp => self.send_tcp(addr, request).await,
            KdcProtocol::Auto => {
                let udp = self.send_udp(addr.clone(), request).await;
                match udp {
                    Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => {
                        self.send_tcp(addr, request).await
                    }
                    Ok(response) => Ok(response),
                    Err(_) => self.send_tcp(addr, request).await,
                }
            }
        }
    }

    /// Discover KDC endpoints for a realm using `krb5.conf` semantics.
    ///
    /// Configured `[realms]` KDCs are preferred. DNS SRV lookup is attempted
    /// only when no KDCs are configured and `dns_lookup_kdc = true`.
    pub async fn discover_kdcs(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        if let Some(realm_entry) = config.realm(realm)
            && !realm_entry.kdc.is_empty()
        {
            return realm_entry
                .kdc
                .iter()
                .map(|value| KdcEndpoint::configured(protocol, value))
                .collect();
        }

        if config.libdefaults.dns_lookup_kdc {
            return self.discover_kdcs_with_dns(realm, protocol).await;
        }

        if config.realm(realm).is_some() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Err(crate::config::Error::NoRealm(realm.to_owned()).into())
        }
    }

    /// Discover kpasswd endpoints for a realm.
    ///
    /// Configured `[realms]` kpasswd servers are preferred. DNS SRV lookup is
    /// attempted only when no password-change servers are configured and
    /// `dns_lookup_kdc = true`.
    pub async fn discover_kpasswd_servers(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        if let Some(realm_entry) = config.realm(realm)
            && !realm_entry.kpasswd_server.is_empty()
        {
            return realm_entry
                .kpasswd_server
                .iter()
                .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
                .collect();
        }

        if config.libdefaults.dns_lookup_kdc {
            return self
                .discover_kpasswd_servers_with_dns(realm, protocol)
                .await;
        }

        config
            .configured_kpasswd_servers(realm)?
            .iter()
            .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
            .collect()
    }

    /// Send an encoded request to the first reachable KDC discovered from config.
    pub async fn send_to_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if protocol == KdcProtocol::Auto {
            return self.send_to_realm_auto(config, realm, request).await;
        }
        self.send_to_realm_explicit(config, protocol, realm, request)
            .await
    }

    async fn send_to_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send an encoded kpasswd request to the first reachable configured server.
    pub async fn send_to_kpasswd_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if protocol == KdcProtocol::Auto {
            return self
                .send_to_kpasswd_realm_auto(config, realm, request)
                .await;
        }
        self.send_to_kpasswd_realm_explicit(config, protocol, realm, request)
            .await
    }

    async fn send_to_kpasswd_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self
            .discover_kpasswd_servers(config, realm, protocol)
            .await?;
        self.send_to_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send a framed kpasswd request through Tokio transport and parse the reply.
    pub async fn exchange_kpasswd_request<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &crate::kadmin::Request,
    ) -> Result<crate::kadmin::Reply, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let frame = request.encode()?;
        let response = self.send(protocol, addr, &frame).await?;
        Ok(crate::kadmin::Reply::parse(&response)?)
    }

    /// Send a framed kpasswd request to a configured kpasswd server and parse the reply.
    pub async fn exchange_kpasswd_request_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &crate::kadmin::Request,
    ) -> Result<crate::kadmin::Reply, Error> {
        let frame = request.encode()?;
        let response = self
            .send_to_kpasswd_realm(config, protocol, realm, &frame)
            .await?;
        Ok(crate::kadmin::Reply::parse(&response)?)
    }

    /// Send a framed kpasswd request and return a checked password-change result.
    pub async fn exchange_kpasswd_result<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &crate::kadmin::Request,
        reply_key: &EncryptionKey,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let reply = self
            .exchange_kpasswd_request(protocol, addr, request)
            .await?;
        let result = reply.decrypt_result(reply_key)?;
        result.ensure_success()?;
        Ok(result)
    }

    /// Send a framed kpasswd request to a configured server and return a checked result.
    pub async fn exchange_kpasswd_result_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &crate::kadmin::Request,
        reply_key: &EncryptionKey,
    ) -> Result<crate::kadmin::ChangePasswordResult, Error> {
        let reply = self
            .exchange_kpasswd_request_with_config(config, protocol, realm, request)
            .await?;
        let result = reply.decrypt_result(reply_key)?;
        result.ensure_success()?;
        Ok(result)
    }

    /// Send an AS-REQ through Tokio transport and process the returned AS-REP.
    pub async fn exchange_as_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send an AS-REQ through a config-discovered KDC and process the AS-REP.
    pub async fn exchange_as_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send a TGS-REQ through Tokio transport and process the returned TGS-REP.
    pub async fn exchange_tgs_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Send a TGS-REQ through a config-discovered KDC and process the TGS-REP.
    pub async fn exchange_tgs_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
            .await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Perform S4U2Self through an explicit KDC endpoint.
    pub async fn s4u2self<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        user: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform S4U2Self through a config-discovered KDC.
    pub async fn s4u2self_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        user: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Perform S4U2Proxy through an explicit KDC endpoint.
    pub async fn s4u2proxy<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform S4U2Proxy through a config-discovered KDC.
    pub async fn s4u2proxy_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Renew an existing TGT through an explicit KDC endpoint.
    pub async fn renew_tgt<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        tgt: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing TGT through a config-discovered KDC.
    pub async fn renew_tgt_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing service ticket through an explicit KDC endpoint.
    pub async fn renew_ticket<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        ticket: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &ticket.session_key)
            .await
    }

    /// Renew an existing service ticket through a config-discovered KDC.
    pub async fn renew_ticket_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        ticket: &AsRepSession,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &ticket.session_key)
            .await
    }

    /// Acquire a service ticket, following cross-realm TGS referrals.
    ///
    /// The supplied `tgt` is used as the starting TGT. If the service belongs
    /// to a different realm, this first obtains referral TGTs until it can ask
    /// the target realm for the final service ticket.
    pub async fn get_service_ticket_with_referrals(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReqOptions,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace(config, protocol, tgt, service, options)
            .await?
            .ticket)
    }

    /// Acquire a service ticket and return intermediate referral TGTs.
    pub async fn get_service_ticket_with_referral_trace(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReqOptions,
    ) -> Result<ReferralTgsResult, Error> {
        self.get_service_ticket_with_referral_trace_limit(
            config,
            protocol,
            tgt,
            service,
            options,
            DEFAULT_MAX_REFERRALS,
        )
        .await
    }

    /// Acquire a service ticket with an explicit referral limit.
    pub async fn get_service_ticket_with_referrals_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReqOptions,
        max_referrals: usize,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace_limit(
                config,
                protocol,
                tgt,
                service,
                options,
                max_referrals,
            )
            .await?
            .ticket)
    }

    /// Acquire a service ticket with an explicit referral limit, returning the referral trace.
    pub async fn get_service_ticket_with_referral_trace_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        mut service: Principal,
        options: TgsReqOptions,
        max_referrals: usize,
    ) -> Result<ReferralTgsResult, Error> {
        let mut current_tgt = tgt.clone();
        let mut current_realm =
            tgt_realm(&current_tgt).ok_or_else(|| Error::InvalidReferralTicket {
                service: current_tgt.service.name(),
            })?;
        if service.realm.is_empty() {
            service.realm =
                service_realm(config, &service).unwrap_or_else(|| current_realm.clone());
        }
        let target_realm = service.realm.clone();
        let mut referral_tgts = Vec::new();

        for referrals in 0..=max_referrals {
            let requested_service = if current_realm == target_realm {
                service.clone()
            } else {
                Principal::new(
                    current_realm.clone(),
                    KRB_NT_SRV_INST,
                    ["krbtgt".to_owned(), target_realm.clone()],
                )
            };
            let request = build_tgs_req_for_realm(
                &current_tgt,
                current_realm.clone(),
                requested_service,
                options.clone(),
            )?;
            let response = self
                .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
                .await?;
            let ticket =
                process_tgs_rep_with_referral(&request, &response, &current_tgt.session_key)?;

            if principal_matches(&ticket.service, &service) {
                return Ok(ReferralTgsResult {
                    ticket,
                    referral_tgts,
                });
            }

            let referred_realm =
                tgt_realm(&ticket).ok_or_else(|| Error::ServicePrincipalMismatch {
                    expected: service.name(),
                    actual: ticket.service.name(),
                })?;
            if referred_realm == current_realm {
                return Err(Error::InvalidReferralTicket {
                    service: ticket.service.name(),
                });
            }

            current_realm = referred_realm;
            referral_tgts.push(ticket.clone());
            current_tgt = ticket;

            if referrals == max_referrals {
                return Err(Error::MaxReferralDepth { max: max_referrals });
            }
        }

        Err(Error::MaxReferralDepth { max: max_referrals })
    }

    /// Perform a TGT AS login using password credentials and KDC preauth hints.
    pub async fn login_tgt_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password(protocol, addr, client, service, password, options)
            .await
    }

    /// Perform an AS login for an explicit service using password credentials and KDC preauth hints.
    pub async fn login_as_service_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
        let initial_response = self
            .send(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, service, password, options, &initial_response)?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a password TGT AS login using KDCs discovered from `krb5.conf`.
    pub async fn login_tgt_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password_config(
            config, protocol, client, service, password, options,
        )
        .await
    }

    /// Perform a password AS login for an explicit service using KDCs discovered from `krb5.conf`.
    pub async fn login_as_service_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        password: &[u8],
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let initial_request =
            password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
        let initial_response = self
            .send_to_realm(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, service, password, options, &initial_response)?;
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a TGT AS login using keytab credentials and KDC preauth hints.
    pub async fn login_tgt_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab(protocol, addr, client, service, keytab, options)
            .await
    }

    /// Perform an AS login for an explicit service using keytab credentials and KDC preauth hints.
    pub async fn login_as_service_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
        let initial_response = self
            .send(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, service, keytab, options, &initial_response)?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a keytab TGT AS login using KDCs discovered from `krb5.conf`.
    pub async fn login_tgt_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab_config(config, protocol, client, service, keytab, options)
            .await
    }

    /// Perform a keytab AS login for an explicit service using KDCs discovered from `krb5.conf`.
    pub async fn login_as_service_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        options: AsReqOptions,
    ) -> Result<AsRepSession, Error> {
        let initial_request =
            keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
        let initial_response = self
            .send_to_realm(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, service, keytab, options, &initial_response)?;
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        process_as_rep(&request, &response, &reply_key)
    }

    async fn discover_kdcs_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let endpoints = self
            .discover_srv_endpoints("_kerberos", realm, protocol)
            .await?;
        if endpoints.is_empty() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Ok(endpoints)
        }
    }

    async fn discover_kpasswd_servers_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        match self
            .discover_srv_endpoints("_kpasswd", realm, protocol)
            .await
        {
            Ok(endpoints) if !endpoints.is_empty() => return Ok(endpoints),
            Ok(_) | Err(_) => {}
        }

        let endpoints = self
            .discover_srv_endpoints("_kerberos-adm", realm, protocol)
            .await?;
        if endpoints.is_empty() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Ok(endpoints)
        }
    }

    async fn discover_srv_endpoints(
        &self,
        service: &str,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let transport = match protocol {
            KdcProtocol::Udp | KdcProtocol::Auto => "_udp",
            KdcProtocol::Tcp => "_tcp",
        };
        let query = format!("{service}.{transport}.{realm}.");
        let resolver = TokioResolver::builder_tokio()
            .map_err(|source| Error::DnsResolverConfig(source.to_string()))?
            .build()
            .map_err(|source| Error::DnsResolverConfig(source.to_string()))?;
        let lookup = resolver
            .srv_lookup(query.as_str())
            .await
            .map_err(|source| Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol,
                message: source.to_string(),
            })?;

        let mut records = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(srv) => Some(srv),
                _ => None,
            })
            .map(|srv| {
                (
                    srv.priority,
                    srv.weight,
                    srv.target.to_utf8().trim_end_matches('.').to_owned(),
                    srv.port,
                )
            })
            .filter(|(_, _, target, _)| !target.is_empty() && target != ".")
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
        });

        Ok(records
            .into_iter()
            .map(|(_, _, host, port)| KdcEndpoint {
                protocol,
                host,
                port,
                source: KdcEndpointSource::DnsSrv,
            })
            .collect())
    }

    async fn send_to_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if endpoints.is_empty() {
            return Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            });
        }

        let mut failures = Vec::new();
        for endpoint in endpoints {
            match self
                .send(
                    endpoint.protocol,
                    (endpoint.host.as_str(), endpoint.port),
                    request,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => failures.push(format!("{}: {error}", endpoint.authority())),
            }
        }

        Err(Error::KdcEndpointFailures {
            realm: realm.to_owned(),
            protocol,
            failures,
        })
    }

    async fn send_to_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let udp_first = auto_uses_udp_first(config, request.len());
        let (first, second) = if udp_first {
            (KdcProtocol::Udp, KdcProtocol::Tcp)
        } else {
            (KdcProtocol::Tcp, KdcProtocol::Udp)
        };

        match self
            .send_to_realm_explicit(config, first, realm, request)
            .await
        {
            Ok(response)
                if first == KdcProtocol::Udp
                    && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) =>
            {
                self.send_to_realm_explicit(config, second, realm, request)
                    .await
            }
            Ok(response) => Ok(response),
            Err(_) => {
                self.send_to_realm_explicit(config, second, realm, request)
                    .await
            }
        }
    }

    async fn send_to_kpasswd_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let udp_first = auto_uses_udp_first(config, request.len());
        let (first, second) = if udp_first {
            (KdcProtocol::Udp, KdcProtocol::Tcp)
        } else {
            (KdcProtocol::Tcp, KdcProtocol::Udp)
        };

        match self
            .send_to_kpasswd_realm_explicit(config, first, realm, request)
            .await
        {
            Ok(response)
                if first == KdcProtocol::Udp
                    && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) =>
            {
                self.send_to_kpasswd_realm_explicit(config, second, realm, request)
                    .await
            }
            Ok(response) => Ok(response),
            Err(_) => {
                self.send_to_kpasswd_realm_explicit(config, second, realm, request)
                    .await
            }
        }
    }

    async fn with_transport_timeout<F, T>(&self, operation: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        tokio::time::timeout(self.timeout, operation)
            .await
            .map_err(|_| Error::TransportTimeout(self.timeout))?
    }
}

#[cfg(feature = "tokio")]
fn non_empty_kdc_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
    if response.is_empty() {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(response)
}

#[cfg(feature = "tokio")]
fn parse_kdc_endpoint(value: &str, default_port: u16) -> Result<(String, u16), Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidKdcEndpoint(value.to_owned()));
    }

    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        };
        if host.is_empty() {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        }
        let port = if let Some(port) = suffix.strip_prefix(':') {
            parse_kdc_port(value, port)?
        } else if suffix.is_empty() {
            default_port
        } else {
            return Err(Error::InvalidKdcEndpoint(value.to_owned()));
        };
        return Ok((host.to_owned(), port));
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.ends_with(':')
    {
        return Ok((host.to_owned(), parse_kdc_port(value, port)?));
    }

    if value.matches(':').count() == 1 {
        return Err(Error::InvalidKdcEndpoint(value.to_owned()));
    }

    Ok((value.to_owned(), default_port))
}

#[cfg(feature = "tokio")]
fn parse_kdc_port(endpoint: &str, port: &str) -> Result<u16, Error> {
    port.parse::<u16>()
        .map_err(|_| Error::InvalidKdcEndpoint(endpoint.to_owned()))
}

#[cfg(feature = "tokio")]
fn kdc_error_code(bytes: &[u8]) -> Option<i32> {
    crate::krb_error::decode_krb_error(bytes)
        .ok()
        .map(|error| error.error_code)
}

#[cfg(feature = "tokio")]
fn auto_uses_udp_first(config: &Config, request_len: usize) -> bool {
    let limit = config.libdefaults.udp_preference_limit;
    limit != 1 && limit >= 0 && request_len <= limit as usize
}
