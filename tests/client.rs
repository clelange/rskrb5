#![cfg(feature = "messages")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use rskrb5::ccache;
use rskrb5::client::KpasswdRequestOptions;
use rskrb5::client::{
    AP_REP_ENCPART_USAGE, AP_REQ_AUTHENTICATOR_USAGE, AS_REP_ENCPART_USAGE, AS_REQ_CHECKSUM_USAGE,
    AS_REQ_PA_ENC_TIMESTAMP_USAGE, ApReqOptions, AsReqOptions, BuiltAsReq, BuiltTgsReq, Error,
    KDC_ERR_PREAUTH_REQUIRED, KDC_OPTION_CANONICALIZE, KDC_OPTION_CNAME_IN_ADDL_TKT,
    KDC_OPTION_RENEW, KDC_OPTION_RENEWABLE, KdcError, KdcTransport, PA_ENC_TIMESTAMP,
    PA_ETYPE_INFO2, PA_FOR_USER, PA_FOR_USER_CHECKSUM_USAGE, PA_FX_FAST, PA_PAC_OPTIONS,
    PA_REQ_ENC_PA_REP, PA_TGS_REQ, PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION,
    PreauthKeyInfo, Principal, TGS_REP_ENCPART_SESSION_KEY_USAGE,
    TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE, TGS_REQ_AUTHENTICATOR_USAGE, TICKET_FLAG_ENC_PA_REP,
    TgsReqOptions, build_ap_req_with_confounder, build_kpasswd_request,
    build_kpasswd_request_with_confounders, build_preauthenticated_as_req,
    build_s4u2proxy_req_with_confounder, build_s4u2self_req_with_confounder,
    build_tgs_req_for_realm_with_confounder, build_tgs_req_with_confounder, build_tgt_as_req,
    build_tgt_renewal_req_with_confounder, build_ticket_renewal_req_with_confounder,
    default_password_salt, derive_password_reply_key, exchange_as_req, exchange_tgs_req,
    login_as_service_with_keytab, login_as_service_with_password, login_tgt_with_keytab,
    login_tgt_with_password, pa_enc_timestamp_with_confounder, pa_for_user_padata,
    pa_pac_options_padata, process_as_rep, process_kdc_error, process_tgs_rep,
    process_tgs_rep_with_referral, renew_tgt, renew_ticket, s4u_byte_array, s4u2proxy, s4u2self,
    select_preauth_key_info, verify_kpasswd_ap_rep,
};
#[cfg(all(feature = "tokio", feature = "spnego"))]
use rskrb5::client::{BlockingNegotiateClient, NegotiateClient};
#[cfg(feature = "tokio")]
use rskrb5::client::{KdcProtocol, PrunedSessions, TokioClient, TokioKdcTransport};
#[cfg(feature = "tokio")]
use rskrb5::config::Config;
use rskrb5::crypto::{AesSha1Etype, KerberosEtype, kerb_checksum_hmac_md5};
use rskrb5::kadmin::{
    ChangePasswdData, EncKrbPrivPartOptions, KPASSWD_SUCCESS, KRB_PRIV_ENCPART_USAGE,
    Reply as KpasswdReply, Request as KpasswdRequest, build_krb_priv_with_confounder,
    ipv4_host_address,
};
use rskrb5::keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal};
use rskrb5::messages::PaReqEncPaRep;
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;

mod common;

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const SERVICE_SESSION_KEY: &str =
    "7b4115955ac25c69929af6b55c47a81db574cbbf615647e385ea38a58e2a7e9a";
const PREAUTH_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const AS_REP_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TGS_REQ_CONFOUNDER: &str = "202122232425262728292a2b2c2d2e2f";
const TGS_REP_CONFOUNDER: &str = "303132333435363738393a3b3c3d3e3f";
const TICKET_FLAGS: &[u8; 4] = &[0x40, 0x81, 0x00, 0x10];
const TESTUSER_PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER_SALT: &str = "TEST.GOKRB5testuser1";

#[path = "client/as_exchange.rs"]
mod as_exchange;
#[path = "client/login_preauth.rs"]
mod login_preauth;
#[path = "client/password_change.rs"]
mod password_change;
#[path = "client/session_cache.rs"]
mod session_cache;
#[path = "client/tgs_exchange.rs"]
mod tgs_exchange;

struct MockTransport {
    expected_realm: String,
    expected_request: Vec<u8>,
    response: Vec<u8>,
    called: bool,
}

impl KdcTransport for MockTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, self.expected_realm);
        assert_eq!(request, self.expected_request.as_slice());
        self.called = true;
        Ok(self.response.clone())
    }
}

struct S4uTransport {
    session_key: EncryptionKey,
    expected_service: Principal,
    expected_user: Principal,
    calls: usize,
}

impl KdcTransport for S4uTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::TgsReq = rasn::der::decode(request).expect("TGS-REQ decodes");
        let body = &decoded.0.req_body;
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
            self.expected_service
        );

        let padata = decoded.0.padata.as_ref().expect("S4U TGS-REQ padata");
        assert_eq!(padata.len(), 2);
        assert_eq!(padata[0].r#type, PA_TGS_REQ);
        assert_eq!(padata[1].r#type, PA_FOR_USER);
        let pa_for_user = rskrb5::messages::PaForUser::decode_der(padata[1].value.as_ref())
            .expect("PA-FOR-USER decodes");
        assert_eq!(
            principal_from_parts(&pa_for_user.user_realm, &pa_for_user.user_name),
            self.expected_user
        );

        self.calls += 1;
        let mut built = built_tgs_request_from_der(decoded, request);
        built.client = self.expected_user.clone();
        Ok(synthetic_tgs_rep(
            &built,
            built.nonce,
            &self.session_key.clone(),
        ))
    }
}

struct S4u2ProxyTransport {
    session_key: EncryptionKey,
    expected_frontend_service: Principal,
    expected_target_service: Principal,
    expected_client: Principal,
    calls: usize,
}

impl KdcTransport for S4u2ProxyTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::TgsReq = rasn::der::decode(request).expect("TGS-REQ decodes");
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
            self.expected_frontend_service
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
            self.expected_target_service
        );

        let padata = decoded.0.padata.as_ref().expect("S4U2Proxy TGS-REQ padata");
        assert_eq!(padata.len(), 1);
        assert_eq!(padata[0].r#type, PA_TGS_REQ);
        let additional_tickets = body
            .additional_tickets
            .as_ref()
            .expect("S4U2Proxy evidence ticket");
        assert_eq!(additional_tickets.len(), 1);
        assert_eq!(
            principal_from_parts(&additional_tickets[0].realm, &additional_tickets[0].sname),
            self.expected_frontend_service
        );

        self.calls += 1;
        let mut built = built_tgs_request_from_der(decoded, request);
        built.client = self.expected_client.clone();
        Ok(synthetic_tgs_rep(
            &built,
            built.nonce,
            &self.session_key.clone(),
        ))
    }
}

struct RenewalTransport {
    session_key: EncryptionKey,
    expected_service: Principal,
    calls: usize,
}

impl KdcTransport for RenewalTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::TgsReq = rasn::der::decode(request).expect("TGS-REQ decodes");
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            (KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW)
                .to_be_bytes()
                .as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
            self.expected_service
        );

        self.calls += 1;
        let built = built_tgs_request_from_der(decoded, request);
        Ok(synthetic_tgs_rep(
            &built,
            built.nonce,
            &self.session_key.clone(),
        ))
    }
}

struct PreauthTransport {
    reply_key: EncryptionKey,
    expected_pa_kvno: Option<u32>,
    expect_fast_negotiation: bool,
    calls: usize,
}

impl PreauthTransport {
    fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
        Self {
            reply_key,
            expected_pa_kvno,
            expect_fast_negotiation: true,
            calls: 0,
        }
    }

    fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.expect_fast_negotiation = fast_negotiation;
        self
    }
}

impl KdcTransport for PreauthTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::AsReq = rasn::der::decode(request).expect("AS-REQ decodes");
        self.calls += 1;
        match self.calls {
            1 => {
                assert_fast_negotiation_marker(&decoded, self.expect_fast_negotiation);
                Ok(synthetic_preauth_required_error())
            }
            2 => {
                assert_fast_negotiation_marker(&decoded, self.expect_fast_negotiation);
                assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno);
                let built = built_request_from_der(decoded, request);
                Ok(synthetic_as_rep_with_reply_key(
                    &built,
                    built.nonce,
                    built.service.clone(),
                    &self.reply_key,
                ))
            }
            _ => panic!("unexpected transport call {}", self.calls),
        }
    }
}

struct AssumedPreauthTransport {
    reply_key: EncryptionKey,
    expected_pa_kvno: Option<u32>,
    calls: usize,
}

impl AssumedPreauthTransport {
    fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
        Self {
            reply_key,
            expected_pa_kvno,
            calls: 0,
        }
    }
}

impl KdcTransport for AssumedPreauthTransport {
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(realm, "TEST.GOKRB5");
        let decoded: rasn_kerberos::AsReq = rasn::der::decode(request).expect("AS-REQ decodes");
        self.calls += 1;
        assert_eq!(self.calls, 1, "assumed preauth should only call KDC once");

        let padata = decoded
            .0
            .padata
            .as_ref()
            .expect("assumed preauth request has padata");
        assert!(
            padata
                .iter()
                .any(|padata| padata.r#type == PA_REQ_ENC_PA_REP),
            "assumed preauth keeps PA-REQ-ENC-PA-REP"
        );
        assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno);

        let built = built_request_from_der(decoded, request);
        Ok(synthetic_as_rep_with_reply_key(
            &built,
            built.nonce,
            built.service.clone(),
            &self.reply_key,
        ))
    }
}

fn sample_request() -> BuiltAsReq {
    build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344),
    )
    .expect("sample request builds")
}

fn sample_request_with_pa_req_enc_pa_rep() -> BuiltAsReq {
    build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReqOptions::new(timestamp(1_893_553_447), 0x1122_3344).with_padata(vec![
            rasn_kerberos::PaData {
                r#type: PA_REQ_ENC_PA_REP,
                value: Vec::new().into(),
            },
        ]),
    )
    .expect("sample request builds")
}

fn sample_tgt_session() -> rskrb5::client::AsRepSession {
    let request = sample_request();
    let response = synthetic_as_rep(&request, request.nonce);
    process_as_rep(&request, &response, &reply_key()).expect("sample TGT validates")
}

fn sample_referral_tgt_session(realm: &str) -> rskrb5::client::AsRepSession {
    let mut tgt = sample_tgt_session();
    tgt.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt".to_owned(), realm.to_owned()]);
    tgt.session_key.value = vec![0x9a; 32];
    tgt.ticket = format!("referral-ticket-{realm}").into_bytes();
    tgt
}

#[cfg(feature = "tokio")]
fn valid_referral_tgt_session(
    tgt: &rskrb5::client::AsRepSession,
    realm: &str,
) -> rskrb5::client::AsRepSession {
    let referral_service = Principal::tgt_service(realm);
    let request = build_tgs_req_with_confounder(
        tgt,
        referral_service.clone(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x8877_6655).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("referral TGS-REQ builds");
    let response =
        synthetic_tgs_rep_with_service(&request, request.nonce, &tgt.session_key, referral_service);
    process_tgs_rep_with_referral(&request, &response, &tgt.session_key)
        .expect("referral TGT validates")
}

#[cfg(feature = "tokio")]
fn current_tgt_session(
    auth_age_minutes: u64,
    remaining_minutes: u64,
) -> rskrb5::client::AsRepSession {
    let now = SystemTime::now();
    let mut tgt = sample_tgt_session();
    tgt.auth_time = now
        .checked_sub(Duration::from_secs(auth_age_minutes * 60))
        .expect("auth time");
    tgt.start_time = tgt.auth_time;
    tgt.end_time = if remaining_minutes == 0 {
        now.checked_sub(Duration::from_secs(60))
            .expect("expired end time")
    } else {
        now.checked_add(Duration::from_secs(remaining_minutes * 60))
            .expect("end time")
    };
    tgt.renew_till = Some(
        now.checked_add(Duration::from_secs(24 * 60 * 60))
            .expect("renew time"),
    );
    tgt.key_expiration = Some(tgt.end_time);
    tgt
}

fn sample_tgs_request(tgt: &rskrb5::client::AsRepSession) -> BuiltTgsReq {
    build_tgs_req_with_confounder(
        tgt,
        sample_service_principal(),
        TgsReqOptions::new(timestamp(1_893_553_450), 0x5566_7788).with_etypes(vec![18]),
        timestamp(1_893_553_451),
        654_321,
        &decode_hex(TGS_REQ_CONFOUNDER),
    )
    .expect("sample TGS-REQ builds")
}

fn sample_built_kpasswd_request() -> rskrb5::client::BuiltKpasswdRequest {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let reply_key = EncryptionKey {
        etype: 18,
        value: vec![0x55; 32],
    };
    let change_data = ChangePasswdData::for_target(b"newpassword", 1, ["testuser1"], "TEST.GOKRB5")
        .expect("ChangePasswdData builds");

    build_kpasswd_request_with_confounders(
        &service_ticket,
        &change_data,
        reply_key,
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
        &decode_hex(TGS_REQ_CONFOUNDER),
        &decode_hex(PREAUTH_CONFOUNDER),
    )
    .expect("kpasswd request builds")
}

fn kpasswd_ap_rep(built: &rskrb5::client::BuiltKpasswdRequest, cusec: u32) -> Vec<u8> {
    let enc_part = rasn_kerberos::EncApRepPart {
        ctime: kerberos_time(1_893_553_452),
        cusec: rasn::types::Integer::from(cusec),
        subkey: None,
        seq_number: Some(99),
    };
    let plaintext = rasn::der::encode(&enc_part).expect("EncApRepPart encodes");
    let cipher = AesSha1Etype::Aes256
        .encrypt_message_with_confounder(
            &built.ap_req.session_key.value,
            &plaintext,
            AP_REP_ENCPART_USAGE,
            &decode_hex(AS_REP_CONFOUNDER),
        )
        .expect("AP-REP encrypts");
    let ap_rep = rasn_kerberos::ApRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(15),
        enc_part: rasn_kerberos::EncryptedData {
            etype: built.ap_req.session_key.etype,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    rasn::der::encode(&ap_rep).expect("AP-REP encodes")
}

fn kpasswd_reply_with_ap_rep(
    built: &rskrb5::client::BuiltKpasswdRequest,
    ap_rep: &[u8],
) -> Vec<u8> {
    let mut body = ap_rep.to_vec();
    body.extend_from_slice(&rasn::der::encode(&built.request.krb_priv).expect("KRB-PRIV encodes"));
    kpasswd_reply_frame(ap_rep.len() as u16, &body)
}

#[cfg(feature = "tokio")]
fn kpasswd_success_reply_with_ap_rep_subkey(
    authenticator: &rasn_kerberos::Authenticator,
    ap_rep_key: &EncryptionKey,
    response_key: &EncryptionKey,
    code: u16,
    text: &str,
) -> Vec<u8> {
    let enc_ap_rep_part = rasn_kerberos::EncApRepPart {
        ctime: authenticator.ctime.clone(),
        cusec: authenticator.cusec.clone(),
        subkey: Some(rasn_encryption_key(response_key)),
        seq_number: authenticator.seq_number,
    };
    let ap_rep = rskrb5::ap_rep::encode_build_ap_rep_with_confounder(
        &enc_ap_rep_part,
        ap_rep_key,
        None,
        &decode_hex(AS_REP_CONFOUNDER),
    )
    .expect("AP-REP encodes");
    let mut result = Vec::with_capacity(2 + text.len());
    result.extend_from_slice(&code.to_be_bytes());
    result.extend_from_slice(text.as_bytes());
    let krb_priv = build_krb_priv_with_confounder(
        result,
        EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1])),
        response_key,
        &decode_hex(PREAUTH_CONFOUNDER),
    )
    .expect("KRB-PRIV builds");
    let krb_priv = rasn::der::encode(&krb_priv).expect("KRB-PRIV encodes");
    let mut body = ap_rep.clone();
    body.extend_from_slice(&krb_priv);
    kpasswd_reply_frame(ap_rep.len() as u16, &body)
}

fn sample_service_principal() -> Principal {
    Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
}

fn change_password_principal() -> Principal {
    Principal::new("TEST.GOKRB5", 1, ["kadmin", "changepw"])
}

#[cfg(feature = "tokio")]
fn sample_service_ticket_session(
    tgt: &rskrb5::client::AsRepSession,
) -> rskrb5::client::TgsRepSession {
    let request = sample_tgs_request(tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates")
}

fn synthetic_as_rep(request: &BuiltAsReq, nonce: u32) -> Vec<u8> {
    synthetic_as_rep_with_ticket_service(request, nonce, request.service.clone())
}

fn synthetic_as_rep_with_ticket_service(
    request: &BuiltAsReq,
    nonce: u32,
    ticket_service: Principal,
) -> Vec<u8> {
    synthetic_as_rep_with_reply_key(request, nonce, ticket_service, &reply_key())
}

fn synthetic_as_rep_with_reply_key(
    request: &BuiltAsReq,
    nonce: u32,
    ticket_service: Principal,
    reply_key: &EncryptionKey,
) -> Vec<u8> {
    let encrypted_pa_data = request_has_padata(request, PA_REQ_ENC_PA_REP)
        .then(|| fast_negotiation_encrypted_padata(request, reply_key, false));
    synthetic_as_rep_with_reply_key_and_encrypted_padata(
        request,
        nonce,
        ticket_service,
        reply_key,
        encrypted_pa_data,
    )
}

fn synthetic_as_rep_with_reply_key_and_encrypted_padata(
    request: &BuiltAsReq,
    nonce: u32,
    ticket_service: Principal,
    reply_key: &EncryptionKey,
    encrypted_pa_data: Option<Vec<rasn_kerberos::PaData>>,
) -> Vec<u8> {
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SESSION_KEY),
    };
    let enc_part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_encryption_key(&session_key),
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(1_893_553_445),
        }],
        nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(TICKET_FLAGS)),
        auth_time: kerberos_time(1_893_553_445),
        start_time: Some(kerberos_time(1_893_553_445)),
        end_time: kerberos_time(1_893_639_845),
        renew_till: Some(kerberos_time(1_894_071_845)),
        srealm: realm(&request.service.realm),
        sname: rasn_principal(&request.service),
        caddr: None,
        encrypted_pa_data,
    });
    let encrypted = encrypt_message(
        reply_key,
        &rasn::der::encode(&enc_part).expect("EncAsRepPart encodes"),
        AS_REP_ENCPART_USAGE,
        AS_REP_CONFOUNDER,
    );
    let as_rep = rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(11),
        padata: None,
        crealm: realm(&request.client.realm),
        cname: rasn_principal(&request.client),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: rasn::types::Integer::from(5),
            realm: realm(&ticket_service.realm),
            sname: rasn_principal(&ticket_service),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: [0xde, 0xad, 0xbe, 0xef].as_slice().into(),
            },
        },
        enc_part: rasn_kerberos::EncryptedData {
            etype: reply_key.etype,
            kvno: Some(3),
            cipher: encrypted.into(),
        },
    });
    rasn::der::encode(&as_rep).expect("AS-REP encodes")
}

fn fast_negotiation_encrypted_padata(
    request: &BuiltAsReq,
    reply_key: &EncryptionKey,
    corrupt_checksum: bool,
) -> Vec<rasn_kerberos::PaData> {
    vec![
        rasn_kerberos::PaData {
            r#type: PA_FX_FAST,
            value: Vec::new().into(),
        },
        pa_req_enc_pa_rep_padata(request, reply_key, corrupt_checksum),
    ]
}

fn pa_req_enc_pa_rep_padata(
    request: &BuiltAsReq,
    reply_key: &EncryptionKey,
    corrupt_checksum: bool,
) -> rasn_kerberos::PaData {
    let etype = KerberosEtype::from_etype_id(reply_key.etype).expect("supported reply key etype");
    let mut checksum = etype
        .checksum(&reply_key.value, &request.der, AS_REQ_CHECKSUM_USAGE)
        .expect("AS-REQ checksum computes");
    if corrupt_checksum {
        checksum[0] ^= 0xff;
    }
    let value = PaReqEncPaRep {
        checksum_type: etype.checksum_type_id(),
        checksum: checksum.into(),
    };
    rasn_kerberos::PaData {
        r#type: PA_REQ_ENC_PA_REP,
        value: value
            .encode_der()
            .expect("PA-REQ-ENC-PA-REP encodes")
            .into(),
    }
}

fn request_has_padata(request: &BuiltAsReq, padata_type: i32) -> bool {
    request
        .message
        .0
        .padata
        .as_ref()
        .is_some_and(|padata| padata.iter().any(|padata| padata.r#type == padata_type))
}

fn synthetic_tgs_rep(
    request: &BuiltTgsReq,
    nonce: u32,
    tgs_session_key: &EncryptionKey,
) -> Vec<u8> {
    synthetic_tgs_rep_with_service(request, nonce, tgs_session_key, request.service.clone())
}

fn synthetic_tgs_rep_with_service(
    request: &BuiltTgsReq,
    nonce: u32,
    tgs_session_key: &EncryptionKey,
    reply_service: Principal,
) -> Vec<u8> {
    let session_key = EncryptionKey {
        etype: 18,
        value: decode_hex(SERVICE_SESSION_KEY),
    };
    let enc_part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_encryption_key(&session_key),
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(1_893_553_445),
        }],
        nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(TICKET_FLAGS)),
        auth_time: kerberos_time(1_893_553_445),
        start_time: Some(kerberos_time(1_893_553_446)),
        end_time: kerberos_time(1_893_560_646),
        renew_till: Some(kerberos_time(1_894_071_846)),
        srealm: realm(&reply_service.realm),
        sname: rasn_principal(&reply_service),
        caddr: None,
        encrypted_pa_data: None,
    });
    let encrypted = encrypt_message(
        tgs_session_key,
        &rasn::der::encode(&enc_part).expect("EncTgsRepPart encodes"),
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
        TGS_REP_CONFOUNDER,
    );
    let tgs_rep = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(13),
        padata: None,
        crealm: realm(&request.client.realm),
        cname: rasn_principal(&request.client),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: rasn::types::Integer::from(5),
            realm: realm(&reply_service.realm),
            sname: rasn_principal(&reply_service),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(4),
                cipher: [0xca, 0xfe, 0xba, 0xbe].as_slice().into(),
            },
        },
        enc_part: rasn_kerberos::EncryptedData {
            etype: tgs_session_key.etype,
            kvno: None,
            cipher: encrypted.into(),
        },
    });
    rasn::der::encode(&tgs_rep).expect("TGS-REP encodes")
}

fn synthetic_preauth_required_error() -> Vec<u8> {
    let etype_info2 = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
        etype: 18,
        salt: Some(kerberos_string(TESTUSER_SALT)),
        s2kparams: Some(vec![0, 0, 16, 0].into()),
    }]);
    let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
        r#type: PA_ETYPE_INFO2,
        value: rasn::der::encode(&etype_info2)
            .expect("ETYPE-INFO2 encodes")
            .into(),
    }]);
    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: KDC_ERR_PREAUTH_REQUIRED,
        crealm: Some(realm("TEST.GOKRB5")),
        cname: Some(rasn_principal(&Principal::user("TEST.GOKRB5", "testuser1"))),
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&Principal::tgt_service("TEST.GOKRB5")),
        e_text: Some(kerberos_string("Additional pre-authentication required")),
        e_data: Some(
            rasn::der::encode(&method_data)
                .expect("METHOD-DATA encodes")
                .into(),
        ),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

fn password_key_info() -> PreauthKeyInfo {
    PreauthKeyInfo {
        etype: 18,
        salt: Some(TESTUSER_SALT.to_owned()),
        s2kparams: Some(vec![0, 0, 16, 0]),
    }
}

fn keytab_with_reply_key(kvno: u32) -> Keytab {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(KeytabEntry {
        principal: KeytabPrincipal {
            realm: "TEST.GOKRB5".to_owned(),
            components: vec!["testuser1".to_owned()],
            name_type: 1,
        },
        timestamp: 1_893_553_440,
        kvno8: kvno as u8,
        key: reply_key(),
        kvno,
    });
    keytab
}

fn assert_pa_enc_timestamp(request: &rasn_kerberos::AsReq, expected_kvno: Option<u32>) {
    let padata = request.0.padata.as_ref().expect("second AS-REQ has padata");
    let pa_enc_timestamp = padata
        .iter()
        .find(|padata| padata.r#type == PA_ENC_TIMESTAMP)
        .expect("second AS-REQ has PA-ENC-TIMESTAMP");
    let encrypted: rasn_kerberos::EncryptedData =
        rasn::der::decode(pa_enc_timestamp.value.as_ref()).expect("encrypted timestamp decodes");
    assert_eq!(encrypted.etype, 18);
    assert_eq!(encrypted.kvno, expected_kvno);
    assert!(!encrypted.cipher.as_ref().is_empty());
}

fn assert_fast_negotiation_marker(request: &rasn_kerberos::AsReq, expected: bool) {
    let marker = request.0.padata.as_ref().and_then(|padata| {
        padata
            .iter()
            .find(|padata| padata.r#type == PA_REQ_ENC_PA_REP)
    });
    if expected {
        let marker = marker.expect("AS-REQ has PA-REQ-ENC-PA-REP");
        assert!(marker.value.as_ref().is_empty());
    } else {
        assert!(
            marker.is_none(),
            "AS-REQ omits PA-REQ-ENC-PA-REP when fast negotiation is disabled"
        );
    }
}

fn built_request_from_der(message: rasn_kerberos::AsReq, der: &[u8]) -> BuiltAsReq {
    let body = &message.0.req_body;
    let client = principal_from_parts(&body.realm, body.cname.as_ref().expect("cname"));
    let service = principal_from_parts(&body.realm, body.sname.as_ref().expect("sname"));
    BuiltAsReq {
        nonce: body.nonce,
        message,
        der: der.to_vec(),
        client,
        service,
    }
}

fn built_tgs_request_from_der(message: rasn_kerberos::TgsReq, der: &[u8]) -> BuiltTgsReq {
    let body = &message.0.req_body;
    let client = principal_from_parts(&body.realm, body.cname.as_ref().expect("cname"));
    let service = principal_from_parts(&body.realm, body.sname.as_ref().expect("sname"));
    let kdc_realm = kerberos_string_to_string(&body.realm);
    let nonce = body.nonce;
    BuiltTgsReq {
        message,
        der: der.to_vec(),
        client,
        service,
        kdc_realm,
        nonce,
    }
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: decode_hex(REPLY_KEY),
    }
}

fn rasn_encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype,
        value: key.value.clone().into(),
    }
}

fn encrypt_message(
    key: &EncryptionKey,
    plaintext: &[u8],
    usage: u32,
    confounder_hex: &str,
) -> Vec<u8> {
    let etype = AesSha1Etype::from_etype_id(key.etype).expect("AES-SHA1 etype is supported");
    etype
        .encrypt_message_with_confounder(&key.value, plaintext, usage, &decode_hex(confounder_hex))
        .expect("message encrypts")
}

fn rasn_principal(value: &Principal) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: value.name_type,
        string: value
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect(),
    }
}

fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Principal {
    Principal::new(
        kerberos_string_to_string(realm),
        name.r#type,
        name.string.iter().map(kerberos_string_to_string),
    )
}

fn realm(value: &str) -> rasn_kerberos::Realm {
    kerberos_string(value)
}

fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .expect("Kerberos string uses permitted characters")
}

fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> String {
    std::str::from_utf8(value.as_bytes())
        .expect("Kerberos string is UTF-8")
        .to_owned()
}

fn kerberos_time(seconds: u64) -> rasn_kerberos::KerberosTime {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds as i64, 0)
        .expect("fixture timestamp is representable");
    let offset = chrono::FixedOffset::east_opt(0).expect("UTC offset exists");
    rasn_kerberos::KerberosTime(utc.with_timezone(&offset))
}

fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> SystemTime {
    UNIX_EPOCH + Duration::new(time.0.timestamp() as u64, time.0.timestamp_subsec_nanos())
}

fn timestamp(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[cfg(feature = "tokio")]
fn make_credential_current(credential: &mut ccache::Credential, now: u32) {
    credential.times.auth_time = now - 60;
    credential.times.start_time = now - 60;
    credential.times.end_time = now + 60 * 60;
    credential.times.renew_till = now + 2 * 60 * 60;
}

#[cfg(feature = "tokio")]
fn make_credential_expired(credential: &mut ccache::Credential, now: u32) {
    credential.times.auth_time = now - 2 * 60 * 60;
    credential.times.start_time = now - 2 * 60 * 60;
    credential.times.end_time = now - 60 * 60;
    credential.times.renew_till = 0;
}

#[cfg(feature = "tokio")]
fn config_without_kdcs() -> Config {
    Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {
 }
"#,
    )
    .expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_kdc() -> Config {
    Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 preferred_preauth_types = 18 17

[realms]
 TEST.GOKRB5 = {
  kdc = kdc.test.gokrb5
 }
"#,
    )
    .expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_kdc_server(server: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {{
  kdc = {server}
 }}
 RESDOM.GOKRB5 = {{
  kdc = {server}
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_client_keytab_name(keytab_name: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_client_keytab_name = {keytab_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_default_ccache_name(cache_name: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 default_ccache_name = {cache_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
fn config_with_kpasswd_server(server: String) -> Config {
    let input = format!(
        r#"
[libdefaults]
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 TEST.GOKRB5 = {{
  kpasswd_server = {server}
 }}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg(feature = "tokio")]
async fn read_tcp_kdc_request(listener: &TcpListener) -> (Vec<u8>, tokio::net::TcpStream) {
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

#[cfg(feature = "tokio")]
async fn serve_s4u2self_tcp_request(
    listener: TcpListener,
    reply_key: EncryptionKey,
    expected_service: Principal,
    expected_user: Principal,
) {
    let (request, mut socket) = read_tcp_kdc_request(&listener).await;
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request).expect("TGS-REQ decodes");
    let body = &decoded.0.req_body;
    assert_eq!(
        principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
        expected_service
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        expected_service
    );

    let padata = decoded.0.padata.as_ref().expect("S4U TGS-REQ padata");
    assert_eq!(padata.len(), 2);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
    assert_eq!(padata[1].r#type, PA_FOR_USER);
    let pa_for_user = rskrb5::messages::PaForUser::decode_der(padata[1].value.as_ref())
        .expect("PA-FOR-USER decodes");
    assert_eq!(
        principal_from_parts(&pa_for_user.user_realm, &pa_for_user.user_name),
        expected_user
    );

    let mut built = built_tgs_request_from_der(decoded, &request);
    built.client = expected_user;
    let response = synthetic_tgs_rep(&built, built.nonce, &reply_key);
    write_tcp_kdc_response(&mut socket, &response).await;
}

#[cfg(feature = "tokio")]
async fn serve_s4u2proxy_tcp_request(
    listener: TcpListener,
    reply_key: EncryptionKey,
    expected_frontend_service: Principal,
    expected_target_service: Principal,
    expected_client: Principal,
) {
    let (request, mut socket) = read_tcp_kdc_request(&listener).await;
    let decoded: rasn_kerberos::TgsReq = rasn::der::decode(&request).expect("TGS-REQ decodes");
    let body = &decoded.0.req_body;
    assert_eq!(
        body.kdc_options.0.as_raw_slice(),
        KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.cname.as_ref().expect("cname")),
        expected_frontend_service
    );
    assert_eq!(
        principal_from_parts(&body.realm, body.sname.as_ref().expect("sname")),
        expected_target_service
    );

    let padata = decoded.0.padata.as_ref().expect("S4U2Proxy TGS-REQ padata");
    assert_eq!(padata.len(), 1);
    assert_eq!(padata[0].r#type, PA_TGS_REQ);
    let additional_tickets = body
        .additional_tickets
        .as_ref()
        .expect("S4U2Proxy evidence ticket");
    assert_eq!(additional_tickets.len(), 1);
    assert_eq!(
        principal_from_parts(&additional_tickets[0].realm, &additional_tickets[0].sname),
        expected_frontend_service
    );

    let mut built = built_tgs_request_from_der(decoded, &request);
    built.client = expected_client;
    let response = synthetic_tgs_rep(&built, built.nonce, &reply_key);
    write_tcp_kdc_response(&mut socket, &response).await;
}

#[cfg(feature = "tokio")]
async fn write_tcp_kdc_response(socket: &mut tokio::net::TcpStream, response: &[u8]) {
    socket
        .write_all(&(response.len() as u32).to_be_bytes())
        .await
        .expect("write response length");
    socket.write_all(response).await.expect("write response");
}

#[cfg(feature = "tokio")]
fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Vec<u8> {
    let message_length = 6 + body.len();
    assert!(u16::try_from(message_length).is_ok());

    let mut frame = Vec::with_capacity(message_length);
    frame.extend_from_slice(&(message_length as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&ap_rep_length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

#[cfg(feature = "tokio")]
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
        error_code: 52,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&change_password_principal()),
        e_text: Some(kerberos_string(text)),
        e_data: Some(e_data.into()),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

#[cfg(feature = "tokio")]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

#[cfg(feature = "tokio")]
fn x_cacheconf_credential(client: &ccache::Principal) -> ccache::Credential {
    ccache::Credential {
        client: client.clone(),
        server: ccache::Principal::new(
            "X-CACHECONF:",
            0,
            vec!["krb5_ccache_conf_data".to_owned(), "fast_avail".to_owned()],
        ),
        key: ccache::EncryptionKey {
            etype: 0,
            value: Vec::new(),
        },
        times: ccache::CredentialTimes::default(),
        is_skey: false,
        ticket_flags: [0; 4],
        addresses: Vec::new(),
        auth_data: Vec::new(),
        ticket: b"yes".to_vec(),
        second_ticket: Vec::new(),
    }
}

#[cfg(feature = "tokio")]
fn matching_credentials<'a>(
    cache: &'a ccache::CCache,
    server: &ccache::Principal,
) -> Vec<&'a ccache::Credential> {
    cache
        .credentials()
        .iter()
        .filter(|credential| {
            credential.client.realm == "TEST.GOKRB5"
                && credential.client.components == ["testuser1"]
                && credential.server == *server
        })
        .collect()
}

#[cfg(feature = "tokio")]
fn temp_client_ccache_file(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-client-{name}-{}-{nanos}",
        std::process::id()
    ))
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
fn save_sample_negotiate_ccache(name: &str) -> (std::path::PathBuf, String) {
    let tgt = sample_tgt_session();
    let mut service_ticket = sample_service_ticket_session(&tgt);
    let now = timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time is after unix epoch")
            .as_secs(),
    );
    service_ticket.auth_time = now.checked_sub(Duration::from_secs(60)).expect("auth time");
    service_ticket.start_time = service_ticket.auth_time;
    service_ticket.end_time = now
        .checked_add(Duration::from_secs(60 * 60))
        .expect("end time");
    service_ticket.renew_till = Some(
        now.checked_add(Duration::from_secs(2 * 60 * 60))
            .expect("renew time"),
    );
    service_ticket.key_expiration = Some(service_ticket.end_time);
    let mut cache = ccache::CCache::new(ccache::Principal::new(
        tgt.client.realm,
        tgt.client.name_type,
        tgt.client.components,
    ));
    cache.upsert_credential(
        service_ticket
            .to_ccache_credential()
            .expect("service ticket exports ccache credential"),
    );
    let path = temp_client_ccache_file(name);
    let name = format!("FILE:{}", path.display());
    cache.save_name(&name).expect("ccache saves by name");
    (path, name)
}

#[cfg(feature = "tokio")]
fn temp_client_ccache_dir(name: &str) -> std::path::PathBuf {
    temp_client_ccache_file(name)
}

#[cfg(feature = "tokio")]
fn temp_client_keytab_file(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-client-keytab-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
