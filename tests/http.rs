#![cfg(feature = "http")]

#[cfg(feature = "tower")]
use std::convert::Infallible;
#[cfg(feature = "tower")]
use std::future::Future;
#[cfg(feature = "tower")]
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

use http_types::header::WWW_AUTHENTICATE;
use http_types::{Request, StatusCode};
use pretty_assertions::assert_eq;
use rskrb5::http as krb_http;
use rskrb5::keytab::Keytab;
use rskrb5::service::ServiceValidator;
use rskrb5::spnego::{self, AcceptedContext, Krb5MechToken, NegTokenInit, SpnegoToken};

#[cfg(feature = "tower")]
use http_types::Response;
#[cfg(feature = "tower")]
use rskrb5::config::Config;
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

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
#[cfg(feature = "tower")]
const KRB5_KTNAME_ENV: &str = "KRB5_KTNAME";
#[cfg(feature = "tower")]
static HTTP_KEYTAB_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const VALID_AP_REQ: &str = concat!(
    "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
    "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
    "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
    "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
    "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
    "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
    "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
    "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
    "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
    "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
    "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
    "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
    "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
    "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
);

#[test]
fn http_helpers_set_headers_and_challenge() {
    let mut request = Request::new(());
    assert!(matches!(
        krb_http::authorization_header(&request),
        Err(krb_http::Error::MissingAuthorization)
    ));

    krb_http::set_authorization_header(&mut request, "Negotiate token").expect("header sets");
    assert_eq!(
        krb_http::authorization_header(&request).expect("header reads"),
        "Negotiate token"
    );

    let response = krb_http::challenge_response::<()>();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("challenge header exists")
            .to_str()
            .expect("challenge header is a string"),
        "Negotiate"
    );
}

#[test]
fn accept_request_validates_spnego_header_and_adds_extension() {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let accepted =
        krb_http::accept_request(&mut validator, &mut request).expect("request validates");

    assert_eq!(accepted.ap_req.client.name(), "testuser1");
    assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
    assert!(
        request.extensions().get::<AcceptedContext>().is_some(),
        "accepted context is attached to request extensions"
    );
}

#[test]
fn accept_request_validates_raw_krb5_header() {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &raw_krb5_authorization_header())
        .expect("authorization header sets");

    let accepted =
        krb_http::accept_request(&mut validator, &mut request).expect("request validates");

    assert_eq!(accepted.ap_req.client.name(), "testuser1");
    assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_challenges_missing_authorization() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab).layer(PanicService);

    let response = run_ready(service.call(Request::new(()))).expect("challenge response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("challenge header exists")
            .to_str()
            .expect("challenge header is a string"),
        "Negotiate"
    );
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_validates_request_and_adds_ap_rep_response_header() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let ap_rep_header = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .expect("AP-REP response header exists")
        .to_str()
        .expect("AP-REP header is a string");
    assert!(matches!(
        spnego::parse_negotiate_header(ap_rep_header).expect("AP-REP header parses"),
        SpnegoToken::Resp(_)
    ));
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_loads_owned_keytab_name() {
    let path = temp_file("http-keytab-name");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");

    let layer = krb_http::NegotiateLayer::from_keytab_name(&name)
        .expect("layer loads keytab name")
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);

    let mut service = layer.layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_loads_config_default_keytab_name() {
    let path = temp_file("http-default-keytab-name");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let config = config_with_default_keytab_name(&name);

    let layer = krb_http::NegotiateLayer::from_default_keytab_name(&config)
        .expect("layer loads default keytab name")
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);

    let mut service = layer.layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_loads_default_keytab_when_env_is_absent() {
    let _guard = HTTP_KEYTAB_ENV_LOCK.lock().expect("HTTP keytab env lock");
    let _env = EnvVarGuard::remove(KRB5_KTNAME_ENV);

    let path = temp_file("http-default-keytab-env-fallback");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let config = config_with_default_keytab_name(&name);

    let layer = krb_http::NegotiateLayer::from_default_keytab(&config)
        .expect("layer loads default keytab")
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);

    let mut service = layer.layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

#[cfg(feature = "tower")]
#[test]
fn tower_service_prefers_env_keytab_over_config_default() {
    let _guard = HTTP_KEYTAB_ENV_LOCK.lock().expect("HTTP keytab env lock");

    let path = temp_file("http-env-keytab-precedence");
    let env_name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let _env = EnvVarGuard::set(KRB5_KTNAME_ENV, &env_name);
    let missing_config_name = format!(
        "FILE:{}",
        temp_file("missing-http-config-default").display()
    );
    let config = config_with_default_keytab_name(&missing_config_name);
    let mut service =
        krb_http::NegotiateService::from_default_keytab(AssertAcceptedService, &config)
            .expect("service loads env keytab before config default")
            .with_now(timestamp(1_893_553_447))
            .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

#[cfg(feature = "tower")]
#[test]
fn tower_layer_rejects_replayed_request() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertAcceptedService);
    let header = valid_authorization_header();
    let mut first = Request::new(());
    krb_http::set_authorization_header(&mut first, &header).expect("authorization header sets");
    let mut replay = Request::new(());
    krb_http::set_authorization_header(&mut replay, &header).expect("authorization header sets");

    let first_response = run_ready(service.call(first)).expect("first response succeeds");
    let replay_response = run_ready(service.call(replay)).expect("replay returns reject response");

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        replay_response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("reject header exists")
            .to_str()
            .expect("reject header is a string"),
        spnego::reject_header().expect("reject header encodes")
    );
}

fn valid_authorization_header() -> String {
    let ap_req_token = Krb5MechToken::ap_req(decode_hex(VALID_AP_REQ))
        .encode()
        .expect("KRB5 AP-REQ token encodes");
    let spnego_token = SpnegoToken::Init(NegTokenInit::krb5(ap_req_token));
    spnego::negotiate_header(&spnego_token).expect("Negotiate header encodes")
}

fn raw_krb5_authorization_header() -> String {
    let ap_req_token = Krb5MechToken::ap_req(decode_hex(VALID_AP_REQ))
        .encode()
        .expect("KRB5 AP-REQ token encodes");
    format!("Negotiate {}", base64_encode(&ap_req_token))
}

fn keytab() -> Keytab {
    Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses")
}

#[cfg(feature = "tower")]
fn config_with_default_keytab_name(keytab_name: &str) -> Config {
    let input = format!(
        r#"
[libdefaults]
 default_keytab_name = {keytab_name}
"#,
    );
    Config::parse(&input).expect("config parses")
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn timestamp(seconds: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[cfg(feature = "tower")]
fn temp_file(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rskrb5-{label}-{nanos}.keytab"))
}

#[cfg(feature = "tower")]
struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

#[cfg(feature = "tower")]
impl EnvVarGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: tests that mutate this key hold HTTP_KEYTAB_ENV_LOCK.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: tests that mutate this key hold HTTP_KEYTAB_ENV_LOCK.
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, previous }
    }
}

#[cfg(feature = "tower")]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: tests that mutate this key hold HTTP_KEYTAB_ENV_LOCK until
        // after the guard is dropped.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[cfg(feature = "tower")]
struct PanicService;

#[cfg(feature = "tower")]
impl Service<Request<()>> for PanicService {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<()>) -> Self::Future {
        panic!("inner service must not be called without credentials")
    }
}

#[cfg(feature = "tower")]
struct AssertAcceptedService;

#[cfg(feature = "tower")]
impl Service<Request<()>> for AssertAcceptedService {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<()>) -> Self::Future {
        let accepted = request
            .extensions()
            .get::<AcceptedContext>()
            .expect("accepted context exists");
        assert_eq!(accepted.ap_req.client.name(), "testuser1");
        assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
        std::future::ready(Ok(Response::new(())))
    }
}

#[cfg(feature = "tower")]
fn run_ready<F>(future: F) -> F::Output
where
    F: Future,
{
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]);
            let low = hex_value(pair[1]);
            (high << 4) | low
        })
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
