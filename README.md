# rskrb5

`rskrb5` is a pure-Rust Kerberos v5 client/service library grown from a
`gokrb5` v8 compatibility effort.

The published `0.1` line is a narrow preview. Pre-`1.0` releases may break
Rust APIs while the crate converges on a smaller, maintainable public surface;
Kerberos wire formats, cryptographic behavior, and fixture parity remain
compatibility-sensitive.

## Current Status

| Area | Status |
|---|---|
| Keytab, ccache, and config files | File-backed keytab and MIT FILE/WRFILE/DIR ccache parsing, serialization, lookup, environment/default-name loading, and redacted metadata JSON are covered by gokrb5 fixtures. |
| Crypto and Kerberos messages | AES-SHA1, AES-SHA2, DES3, RC4-HMAC, DER wrappers, KDC/AP/KRB-PRIV/KRB-SAFE/KRB-CRED helpers, and kpasswd frames are covered by unit vectors and fixture round-trips. |
| High-level client | Tokio password/keytab/ccache login, AS/TGS exchange, referrals, renewal, service-ticket caching, S4U2Self/S4U2Proxy, kpasswd, diagnostics, and ccache write-back are implemented. |
| Service and HTTP Negotiate | AP-REQ validation, replay detection, AP-REP mutual auth, SPNEGO/GSSAPI tokens, HTTP helpers, 401 retry client wrappers, Tower middleware, and an Axum example are implemented. |
| PAC and AD parity | PAC container, validation info, UPN/DNS, credentials, delegation/device/claims data, checksums, and AD-shaped credential summaries are implemented with gated AD tests. |
| Dependency posture | `rasn-kerberos` and `picky-krb` remain evaluation/data-type candidates; AGPL/LGPL Kerberos crates stay out of default/core features. |

## Next Preview Scope

The next pre-`1.0` preview is focused on a smaller, clearer public API around:

- password-backed and file keytab-backed client login;
- FILE, WRFILE, and MIT DIR credential-cache loading/saving;
- default config loading from `KRB5_CONFIG` or platform defaults;
- HTTP Negotiate/SPNEGO header generation and 401 retry wrappers through
  high-level async and blocking clients;
- password change flows through the high-level clients;
- explicit typed rejection of unsupported credential/keytab stores.

Still outside the supported preview scope: API, KCM, KEYRING, and MSLSA
credential stores; FAST; PKINIT; system GSSAPI/SSPI facades; and maintained
Active Directory CI. Lower-level gokrb5 parity modules remain available for
testing and integration work, but their Rust APIs can change before `1.0`.

## Client API Examples

Async HTTP Negotiate from a FILE ccache:

```rust
let config = rskrb5::Config::load_default()?;
let mut client = rskrb5::NegotiateClient::from_ccache_name(
    config,
    "FILE:/tmp/krb5cc",
)?;
let header = client
    .authorization_header_for_host("HTTP", "auth.cern.ch")
    .await?;
```

Transport-agnostic 401 retry wrapper with a replayable request factory
(`http` feature, plus `tokio` when default features are disabled):

```rust
let service = rskrb5::Principal::host_based_service("HTTP", "auth.cern.ch")?;
let result = rskrb5::http::send_with_negotiate(
    &mut client,
    service,
    || {
        http::Request::builder()
            .uri("https://auth.cern.ch/protected")
            .body(Vec::new())
            .expect("request builds")
    },
    |request| async move {
        // Adapt this request to reqwest, hyper, or another HTTP client.
        send_http(request).await
    },
)
.await?;
let response = result.into_response();
```

The request factory may be called twice: once for the initial request and again
after a `401 WWW-Authenticate: Negotiate` challenge.

Blocking CLI-style use:

```rust
let config = rskrb5::Config::load_default_or_parse(include_str!("krb5.conf"))?;
let mut client = rskrb5::BlockingNegotiateClient::from_default_ccache(config)?;
let header = client.authorization_header_for_host("HTTP", "auth.cern.ch")?;
```

Unsupported credential stores remain typed:

```rust
let error = rskrb5::NegotiateClient::from_ccache_name(
    rskrb5::Config::new(),
    "API:",
)
.expect_err("API caches are not implemented");
```

Generate the compatibility report:

```sh
cargo run --no-default-features --features evaluation --bin rskrb5-compat-report
```

The report records the gokrb5 v8 test contract and the current support matrix
for candidate crates. Keep it current whenever a candidate or porting milestone
changes.

Track release parity against the pinned upstream target in
[`docs/gokrb5-parity.md`](docs/gokrb5-parity.md). The machine-readable parity
manifest is [`docs/gokrb5-parity.toml`](docs/gokrb5-parity.toml).

Run the Axum Negotiate example with a service keytab:

```sh
KRB5_KTNAME=FILE:/path/to/http.keytab cargo run --example axum-negotiate --features http --no-default-features
```

Run the local checks:

```sh
cargo fmt --check
cargo check --no-default-features
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --all-features --no-deps
cargo package --locked
prek run --all-files --stage pre-push
```

The GitHub workflow includes a manual Docker-backed integration job. Run it from
`workflow_dispatch` with the `integration` input to exercise the live MIT KDC,
HTTP, DNS, ccache, referral, renewal, and kpasswd-gated integration suite; it
preserves the gokrb5-style `INTEGRATION=1`, `TESTPRIVILEGED=1`, and optional
`TESTAD=1` and `TEST_KPASSWD=1` gates.

For local runs, use [`scripts/run-gated-integration.sh`](scripts/run-gated-integration.sh);
the detailed fixture setup and DNS resolver notes are documented in
[`docs/gated-integration.md`](docs/gated-integration.md).

The live kpasswd integration test also requires the `test_kpasswd` workflow
input because it temporarily changes the Docker test principal password before
restoring it. Use `TEST_KPASSWD_ADDR`, `TEST_KPASSWD_PORT`, and
`TEST_KPASSWD_SADDR` when the password-change service or sender address differs
from the localhost defaults.

The Active Directory integration tests mirror gokrb5's `TESTAD=1` cases but
require a maintained two-domain AD lab. Use
[`docs/ad-integration.md`](docs/ad-integration.md) for the realm, principal,
SPN, endpoint, and strict `TESTAD_REQUIRED=1` release-evidence contract. The
operational setup is split into
[`docs/ad-lab-provisioning.md`](docs/ad-lab-provisioning.md) for the lab and
[`docs/github-ad-gate-setup.md`](docs/github-ad-gate-setup.md) for the
self-hosted Actions runner and secrets.

## Distribution Direction

Source, CI, issues, and releases live on GitHub. Public Rust distribution uses
crates.io. The concrete release gate and checklist are documented in
[`docs/publishing.md`](docs/publishing.md), with preview-specific API notes in
[`docs/release-notes.md`](docs/release-notes.md).
