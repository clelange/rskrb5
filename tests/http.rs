#![cfg(feature = "http")]

#[cfg(feature = "tokio")]
use std::cell::{Cell, RefCell};
#[cfg(any(feature = "tokio", feature = "tower"))]
use std::convert::Infallible;
#[cfg(feature = "tower")]
use std::future::Future;
#[cfg(feature = "tokio")]
use std::rc::Rc;
#[cfg(feature = "tower")]
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

use http_types::header::{HeaderValue, WWW_AUTHENTICATE};
use http_types::{Request, Response, StatusCode};
use pretty_assertions::assert_eq;
use rskrb5::http as krb_http;
use rskrb5::keytab::{EncryptionKey, Keytab};
use rskrb5::service::ServiceValidator;
use rskrb5::spnego::{
    self, AcceptedContext, InitiatorContextOptions, Krb5MechToken, NegTokenInit, SpnegoToken,
};

use rskrb5::client::{AsRepSession, Principal};
#[cfg(feature = "tokio")]
use rskrb5::client::{BlockingNegotiateClient, KdcProtocol, NegotiateClient, TokioClient};
#[cfg(any(feature = "tokio", feature = "tower"))]
use rskrb5::config::Config;
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

mod common;

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
const VALID_SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";

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

#[test]
fn http_helpers_scan_www_authenticate_negotiate_challenges() {
    let mut missing = Response::new(());
    assert!(matches!(
        krb_http::www_authenticate_negotiate_header(&missing),
        Err(krb_http::Error::MissingWwwAuthenticate)
    ));

    missing.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test, local\""),
    );
    assert!(matches!(
        krb_http::www_authenticate_negotiate_header(&missing),
        Err(krb_http::Error::MissingNegotiateChallenge)
    ));

    let challenge = krb_http::challenge_response::<()>();
    assert_eq!(
        krb_http::www_authenticate_negotiate_header(&challenge).expect("bare challenge is found"),
        "Negotiate"
    );

    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test, local\""),
    );
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("negotiate response-token"),
    );
    assert_eq!(
        krb_http::www_authenticate_negotiate_header(&response)
            .expect("Negotiate challenge is found"),
        "negotiate response-token"
    );
}

#[cfg(feature = "tokio")]
#[test]
fn authorize_request_context_sets_header_and_returns_context() {
    runtime().block_on(async {
        let service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        client.cache_service_ticket(service_ticket);
        let mut request = Request::new(());

        let context = krb_http::authorize_request_context_with_options(
            &mut client,
            &mut request,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
        )
        .await
        .expect("request is authorized");

        assert_eq!(context.sequence_number, Some(42));
        assert_eq!(
            krb_http::authorization_header(&request).expect("Authorization header exists"),
            context.header
        );
    });
}

#[cfg(feature = "tokio")]
#[test]
fn authorize_request_context_supports_negotiate_client_wrapper() {
    runtime().block_on(async {
        let mut service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut tokio_client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client.cache_service_ticket(service_ticket.clone());
        let mut client = NegotiateClient::from_tokio_client(tokio_client);
        let mut request = Request::new(());

        let context = krb_http::authorize_request_context_with_negotiate_client_options(
            &mut client,
            &mut request,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(7)),
        )
        .await
        .expect("request is authorized");

        assert_eq!(context.sequence_number, Some(7));
        assert_eq!(
            krb_http::authorization_header(&request).expect("Authorization header exists"),
            context.header
        );

        service_ticket.session_key.value = vec![0x55; 32];
        assert_ne!(context.session_key, service_ticket.session_key);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn negotiate_http_client_retries_challenge_with_replayable_request() {
    runtime().block_on(async {
        let service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut tokio_client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client.cache_service_ticket(service_ticket);
        let mut client = NegotiateClient::from_tokio_client(tokio_client);
        let make_calls = Rc::new(Cell::new(0usize));
        let make_calls_for_factory = Rc::clone(&make_calls);
        let sent = Rc::new(RefCell::new(Vec::<(Option<String>, Vec<u8>)>::new()));
        let sent_for_sender = Rc::clone(&sent);

        let result = krb_http::send_with_negotiate_options(
            &mut client,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(99)),
            move || {
                let call = make_calls_for_factory.get() + 1;
                make_calls_for_factory.set(call);
                Request::builder()
                    .method("POST")
                    .uri("/protected")
                    .body(format!("payload-{call}").into_bytes())
                    .expect("request builds")
            },
            move |request: Request<Vec<u8>>| {
                let authorization = krb_http::authorization_header(&request)
                    .ok()
                    .map(str::to_owned);
                let body = request.body().clone();
                let call = {
                    let mut sent = sent_for_sender.borrow_mut();
                    sent.push((authorization.clone(), body));
                    sent.len()
                };
                let response = if call == 1 {
                    krb_http::challenge_response::<Vec<u8>>()
                } else {
                    let header = authorization.expect("retry request has authorization");
                    assert!(
                        header.starts_with("Negotiate "),
                        "retry Authorization uses Negotiate"
                    );
                    response_with_www_authenticate_body(
                        &spnego::accept_completed_header().expect("accept-completed header"),
                        b"ok".to_vec(),
                    )
                };
                std::future::ready(Ok::<_, Infallible>(response))
            },
        )
        .await
        .expect("Negotiate send succeeds");

        assert!(result.did_negotiate());
        assert_eq!(
            result
                .context
                .as_ref()
                .expect("context is retained")
                .sequence_number,
            Some(99)
        );
        assert!(matches!(
            result.negotiation,
            Some(krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        ));
        assert_eq!(result.response.status(), StatusCode::OK);
        assert_eq!(result.response.body().as_slice(), b"ok");
        assert_eq!(make_calls.get(), 2);

        let sent = sent.borrow();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].0.is_none(), "initial request is unauthenticated");
        assert_eq!(sent[0].1.as_slice(), b"payload-1");
        assert!(
            sent[1]
                .0
                .as_deref()
                .expect("retry has Authorization")
                .starts_with("Negotiate ")
        );
        assert_eq!(sent[1].1.as_slice(), b"payload-2");
    });
}

#[cfg(feature = "tokio")]
#[test]
fn negotiate_http_client_returns_first_response_without_challenge() {
    runtime().block_on(async {
        let mut client = NegotiateClient::with_password(
            Config::new(),
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        let make_calls = Cell::new(0usize);
        let send_calls = Cell::new(0usize);

        let result = krb_http::send_with_negotiate(
            &mut client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            || {
                make_calls.set(make_calls.get() + 1);
                Request::new(())
            },
            |request| {
                assert!(
                    krb_http::authorization_header(&request).is_err(),
                    "unchallenged request should not be preauthenticated"
                );
                send_calls.set(send_calls.get() + 1);
                std::future::ready(Ok::<_, Infallible>(Response::new("public")))
            },
        )
        .await
        .expect("send succeeds");

        assert!(!result.did_negotiate());
        assert!(result.context.is_none());
        assert!(result.negotiation.is_none());
        assert_eq!(*result.response.body(), "public");
        assert_eq!(make_calls.get(), 1);
        assert_eq!(send_calls.get(), 1);
    });
}

#[cfg(feature = "tokio")]
#[test]
fn blocking_negotiate_http_client_returns_first_response_without_challenge() {
    let mut client = BlockingNegotiateClient::with_password(
        Config::new(),
        Principal::user("TEST.GOKRB5", "testuser1"),
        b"unused".to_vec(),
    )
    .expect("blocking client builds");
    let make_calls = Cell::new(0usize);
    let send_calls = Cell::new(0usize);

    let result = krb_http::send_with_blocking_negotiate(
        &mut client,
        Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
        || {
            make_calls.set(make_calls.get() + 1);
            Request::new(())
        },
        |request| {
            assert!(
                krb_http::authorization_header(&request).is_err(),
                "unchallenged request should not be preauthenticated"
            );
            send_calls.set(send_calls.get() + 1);
            Ok::<_, Infallible>(Response::new("public"))
        },
    )
    .expect("send succeeds");

    assert!(!result.did_negotiate());
    assert!(result.context.is_none());
    assert!(result.negotiation.is_none());
    assert_eq!(*result.response.body(), "public");
    assert_eq!(make_calls.get(), 1);
    assert_eq!(send_calls.get(), 1);
}

#[test]
fn verify_ap_rep_response_uses_negotiate_www_authenticate_header() {
    let context = initiator_context();
    let response_header = ap_rep_response_header(&context);
    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&response_header).expect("AP-REP header value"),
    );

    let verified = krb_http::verify_ap_rep_response(&context, &response).expect("AP-REP verifies");

    assert_eq!(verified.ctime, context.authenticator_ctime);
    assert_eq!(verified.cusec, context.authenticator_cusec);
    assert_eq!(verified.authenticator_time, context.authenticator_time);
}

#[test]
fn classify_negotiate_response_reports_client_state() {
    let context = initiator_context();
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &Response::new(())),
        krb_http::ClientNegotiateResponse::NoAuthenticateHeader
    );

    let mut basic = Response::new(());
    basic.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &basic),
        krb_http::ClientNegotiateResponse::NoNegotiateChallenge
    );

    assert_eq!(
        krb_http::classify_negotiate_response(&context, &krb_http::challenge_response::<()>()),
        krb_http::ClientNegotiateResponse::Challenge
    );

    let mut later_challenge = Response::new(());
    later_challenge.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    later_challenge
        .headers_mut()
        .append(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &later_challenge),
        krb_http::ClientNegotiateResponse::Challenge
    );

    let accepted_without_ap_rep = response_with_www_authenticate(
        &spnego::accept_completed_header().expect("accept-completed header"),
    );
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &accepted_without_ap_rep),
        krb_http::ClientNegotiateResponse::Accepted { ap_rep: None }
    );

    let rejected = response_with_www_authenticate(&spnego::reject_header().expect("reject header"));
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &rejected),
        krb_http::ClientNegotiateResponse::Rejected
    );

    let ap_rep = response_with_www_authenticate(&ap_rep_response_header(&context));
    let classified = krb_http::classify_negotiate_response(&context, &ap_rep);
    let krb_http::ClientNegotiateResponse::Accepted {
        ap_rep: Some(verified),
    } = classified
    else {
        panic!("expected verified AP-REP, got {classified:?}");
    };
    assert_eq!(verified.ctime, context.authenticator_ctime);
    assert_eq!(verified.cusec, context.authenticator_cusec);

    let malformed = response_with_www_authenticate("Negotiate not-base64");
    assert!(matches!(
        krb_http::classify_negotiate_response(&context, &malformed),
        krb_http::ClientNegotiateResponse::InvalidToken { .. }
    ));

    let wrong_mechanism = response_with_www_authenticate(&valid_authorization_header());
    assert!(matches!(
        krb_http::classify_negotiate_response(&context, &wrong_mechanism),
        krb_http::ClientNegotiateResponse::InvalidToken { .. }
    ));
}

#[test]
fn verify_ap_rep_response_rejects_malformed_and_wrong_tokens() {
    let context = initiator_context();
    let mut malformed = Response::new(());
    malformed.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Negotiate not-base64"),
    );
    assert!(krb_http::verify_ap_rep_response(&context, &malformed).is_err());

    let mut wrong_mechanism = Response::new(());
    wrong_mechanism.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&valid_authorization_header()).expect("SPNEGO init header value"),
    );
    assert!(krb_http::verify_ap_rep_response(&context, &wrong_mechanism).is_err());
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
fn tower_layer_forwards_authenticated_post_body() {
    let keytab = keytab();
    let payload = b"authenticated upload payload".to_vec();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertBodyService {
            expected: payload.clone(),
        });
    let mut request = Request::builder()
        .method("POST")
        .uri("/upload")
        .body(payload)
        .expect("request builds");
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*response.body(), b"authenticated upload payload".len());
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
fn tower_service_loads_keytab_env() {
    let path = temp_file("http-keytab-env");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let _env = common::EnvVarGuard::set_krb5_ktname(&name);

    let mut service = krb_http::NegotiateService::from_keytab_env(AssertAcceptedService)
        .expect("service loads keytab env")
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
fn tower_layer_loads_keytab_env() {
    let path = temp_file("http-layer-keytab-env");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let _env = common::EnvVarGuard::set_krb5_ktname(&name);

    let layer = krb_http::NegotiateLayer::from_keytab_env()
        .expect("layer loads keytab env")
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
    let _env = common::EnvVarGuard::remove_krb5_ktname();

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
    let path = temp_file("http-env-keytab-precedence");
    let env_name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let _env = common::EnvVarGuard::set_krb5_ktname(&env_name);
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

#[cfg(feature = "tower")]
#[test]
fn tower_layer_rejects_replay_across_services() {
    let keytab = keytab();
    let layer = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let mut first_service = layer.clone().layer(AssertAcceptedService);
    let mut second_service = layer.layer(AssertAcceptedService);
    let header = valid_authorization_header();
    let mut first = Request::new(());
    krb_http::set_authorization_header(&mut first, &header).expect("authorization header sets");
    let mut replay = Request::new(());
    krb_http::set_authorization_header(&mut replay, &header).expect("authorization header sets");

    let first_response = run_ready(first_service.call(first)).expect("first response succeeds");
    let replay_response =
        run_ready(second_service.call(replay)).expect("replay returns reject response");

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

fn initiator_context() -> spnego::InitiatorContext {
    spnego::init_sec_context_with_confounder(
        &service_ticket_session_from_valid_ap_req(),
        InitiatorContextOptions::new().with_sequence_number(Some(42)),
        timestamp(1_893_553_447),
        123_456,
        &decode_hex(AP_REP_CONFOUNDER),
    )
    .expect("client SPNEGO context builds")
}

fn ap_rep_response_header(context: &spnego::InitiatorContext) -> String {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)
        .expect("client SPNEGO header validates");
    accepted
        .ap_rep_response_header_with_confounder(&decode_hex(AP_REP_CONFOUNDER), Default::default())
        .expect("AP-REP response header builds")
}

fn service_ticket_session_from_valid_ap_req() -> AsRepSession {
    let ap_req: rasn_kerberos::ApReq =
        rasn::der::decode(&decode_hex(VALID_AP_REQ)).expect("AP-REQ fixture decodes");
    AsRepSession {
        client: Principal::user("TEST.GOKRB5", "testuser1"),
        service: Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
        session_key: EncryptionKey {
            etype: 18,
            value: decode_hex(VALID_SESSION_KEY),
        },
        ticket: rasn::der::encode(&ap_req.ticket).expect("ticket encodes"),
        ticket_flags: [0; 4],
        auth_time: timestamp(1_893_553_445),
        start_time: timestamp(1_893_553_445),
        end_time: timestamp(1_893_639_845),
        renew_till: None,
        key_expiration: None,
    }
}

fn response_with_www_authenticate(header: &str) -> Response<()> {
    response_with_www_authenticate_body(header, ())
}

fn response_with_www_authenticate_body<B>(header: &str, body: B) -> Response<B> {
    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(header).expect("WWW-Authenticate header value"),
    );
    response.map(|_| body)
}

#[cfg(feature = "tokio")]
fn current_service_ticket_session() -> AsRepSession {
    let mut service_ticket = service_ticket_session_from_valid_ap_req();
    let now = std::time::SystemTime::now();
    service_ticket.auth_time = now - Duration::from_secs(1);
    service_ticket.start_time = now - Duration::from_secs(1);
    service_ticket.end_time = now + Duration::from_secs(60);
    service_ticket
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

#[cfg(feature = "tokio")]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
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
struct AssertBodyService {
    expected: Vec<u8>,
}

#[cfg(feature = "tower")]
impl Service<Request<Vec<u8>>> for AssertBodyService {
    type Response = Response<usize>;
    type Error = Infallible;
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
        let accepted = request
            .extensions()
            .get::<AcceptedContext>()
            .expect("accepted context exists");
        assert_eq!(accepted.ap_req.client.name(), "testuser1");
        assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(request.method().as_str(), "POST");
        assert_eq!(request.uri().path(), "/upload");
        assert_eq!(request.body(), &self.expected);
        std::future::ready(Ok(Response::new(request.body().len())))
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
