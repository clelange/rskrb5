use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use rskrb5::http as krb_http;
use rskrb5::keytab::Keytab;
use rskrb5::service::{ApRepOptions, ServiceValidator};
use rskrb5::spnego::AcceptedContext;

#[derive(Clone)]
struct AppState {
    validator: Arc<Mutex<ServiceValidator<'static>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keytab = Box::leak(Box::new(load_keytab()?));
    let state = AppState {
        validator: Arc::new(Mutex::new(ServiceValidator::new(keytab))),
    };

    let app = Router::new()
        .route("/", get(index))
        .layer(middleware::from_fn_with_state(state.clone(), negotiate))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(Extension(context): Extension<AcceptedContext>) -> String {
    format!(
        "authenticated as {}@{}\n",
        context.ap_req.client.name(),
        context.ap_req.client.realm
    )
}

async fn negotiate(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let accepted = {
        let mut validator = state
            .validator
            .lock()
            .expect("validator lock is not poisoned");
        match krb_http::accept_request(&mut validator, &mut request) {
            Ok(accepted) => accepted,
            Err(krb_http::Error::MissingAuthorization | krb_http::Error::InvalidHeader(_)) => {
                return krb_http::challenge_response();
            }
            Err(krb_http::Error::Spnego(_)) => {
                return krb_http::reject_response()
                    .unwrap_or_else(|_| krb_http::challenge_response());
            }
            Err(_) => return krb_http::challenge_response(),
        }
    };

    let ap_rep_header = accepted
        .ap_rep_response_header(ApRepOptions::default())
        .ok();
    let mut response = next.run(request).await;
    if let Some(header) = ap_rep_header
        && let Ok(value) = HeaderValue::from_str(&header)
    {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

fn load_keytab() -> Result<Keytab, Box<dyn Error>> {
    let path = std::env::var_os("KRB5_KTNAME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("http.keytab"));
    let path = path
        .to_string_lossy()
        .strip_prefix("FILE:")
        .map(PathBuf::from)
        .unwrap_or(path);
    Ok(Keytab::parse(&std::fs::read(path)?)?)
}
