# rskrb5

`rskrb5` is a pure-Rust Kerberos v5 client/service library grown from a
`gokrb5` v8 compatibility effort.

The `0.1.x` preview is intentionally narrow: it is useful for client-side
Kerberos login, file-backed keytab and credential-cache handling, and HTTP
Negotiate/SPNEGO header generation, while broader `gokrb5` parity work
continues in the lower-level modules and tests.

## Current Status

- `rasn-kerberos` and `picky-krb` are treated as dependency candidates for
  Kerberos DER/data types.
- The ASN.1 spike now checks 52 gokrb5 unit-test fixtures with separate decode
  and exact DER round-trip expectations for rasn-backed rskrb5 wrappers and
  `picky-krb`.
- The first real modules are `keytab`, `krb5.conf`, `ccache`, `crypto`,
  `client`, `kadmin`, `service`, and `pac`: keytabs parse, serialize, select keys, and generate
  password-derived ktutil-compatible entries from explicit principals or SPN-style names plus redacted metadata JSON against
  gokrb5 fixtures and load/save file-backed `KRB5_KTNAME` and
  `default_keytab_name` values;
  config parsing covers gokrb5-compatible libdefaults including `default_ccache_name`
  and canonicalize KDC option handling,
  `KRB5_CONFIG` path-list loading,
  comment/tab/no-blank-line variants, realm host mappings, domain realm lookup, duration parsing, configured KDC/KPassword server lookup, and gokrb5-shaped JSON export; ccache parsing
  covers MIT file caches, `KRB5CCNAME` load/save plus FILE/WRFILE/DIR cache-name helpers with `%{uid}`/`%{euid}` expansion, opaque ticket bytes,
  server entry lookup, X-CACHECONF configuration entry read/write, redacted metadata JSON, and exact fixture round-trips; crypto covers RFC3961 n-fold, RFC3962
  AES128/AES256-CTS-HMAC-SHA1-96, RFC8009
  AES128/AES256-CTS-HMAC-SHA2, DES3-CBC-SHA1-KD, and RC4-HMAC string-to-key,
  KDF, checksums, and deterministic encrypted-message vectors; message helpers
  preserve gokrb5 EncryptedData signed-kvno DER edge fixtures, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP, and KRB-ERROR timing diagnostics; KRB-CRED helpers decode gokrb5 fixtures and decrypt EncKrbCredPart; kadmin covers
  ChangePasswdData builders, DER decode, exact fixture round-trip, KRB-PRIV payload building, and kpasswd request
  and reply frame parsing plus reply result handling and result-code checks; client AS/TGS exchange primitives
  cover deterministic TGT AS-REQ construction, KRB-ERROR preauthentication
  negotiation and structured timing diagnostics, PA-ENC-TIMESTAMP encryption, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP encrypted-padata validation, a disable-fast-negotiation AS login switch, runtime-neutral and Tokio S4U2Self exchange helpers, and runtime-neutral and Tokio S4U2Proxy request/exchange helpers with impersonated-user reply validation, assumed
  preauthentication, password/keytab TGT and explicit-service AS login helpers, PA-TGS-REQ
  service-ticket acquisition, a KDC transport boundary, Tokio TCP/UDP/auto
  KDC transport with response-too-big fallback and Docker auto-protocol AS/TGS
  coverage, configured/DNS SRV kpasswd transport, typed kpasswd request/reply/result exchanges, complete kpasswd request assembly with generated reply keys, kpasswd AP-REP validation, and a high-level Tokio password-change helper with initial kadmin/changepw ticket acquisition and credential update, `krb5.conf` configured KDC
  discovery, DNS SRV KDC discovery, AS-REP and TGS-REP encrypted-part decryption and validation,
  generic AP-REQ construction, cross-realm TGS referral following with cached
  and renewable referral TGT sessions, renewable AS/TGS request flags, explicit
  TGT/service-ticket renewal helpers, Docker MIT KDC AS/TGS login, TGT
  renewal, old-KDC password/keytab AS/TGS coverage, negative wrong-keytab and invalid-service KDC-error coverage,
  configured-KDC TCP failover, and gated kpasswd change/restore coverage across AES-SHA1, AES-SHA2, DES3, and RC4-HMAC, per-enctype
  keytab AS/TGS integration coverage, gated external `kinit`/`kvno` ccache
  integration, keytab file-name helpers with `%{uid}`/`%{euid}` expansion, explicit env and environment-preferred client keytab loading, ccache credential export/write-back and
  file/env cache-name loading/saving plus environment-preferred default ccache loading/write-back, and a high-level
  Tokio client with password/keytab/ccache credential sources,
  credential attachment, file-name constructors/write-back, configuration validation, multi-realm TGT/session caching/removal,
  gokrb5-style refresh-window checks, explicit primary/realm TGT renewal, cancellable Tokio auto-renewal, affirm-login reuse,
  Docker-backed destroy semantics, service-ticket caching/lookup/removal, S4U2Self acquisition from a current service TGT, unusable-session pruning, redacted key debug output,
  zeroized key material, and gokrb5-shaped JSON
  session/cache snapshots plus structured diagnostics; service validation covers
  gokrb5-generated AP-REQ fixtures, service-ticket decryption, authenticator
  decryption, client matching, ticket time checks, clock skew, replay, and
  replay-cache aging/shared-cache state, address-required behavior, file-name, configured-default, and environment-preferred keytab validators,
  plus AP-REP mutual-auth reply generation and
  verification and verified ticket PAC extraction; SPNEGO/GSSAPI covers KRB5
  mech tokens, RFC4121 MIC and sealed/unsealed Wrap tokens, NegTokenInit/Resp,
  HTTP Negotiate headers with raw KRB5 token fallback, client AP-REQ initiator
  headers from TGS service tickets, live Docker HTTP SPNEGO and raw KRB5 Negotiate acceptance,
  AP-REP response verification, live replay-sequence rejection, and service-side AP-REQ to AP-REP
  response flow;
  HTTP/Tower adapters cover
  generic `http` request helpers and service-side Tower middleware that
  challenges, validates, shares replay detection across layer-built services, forwards authenticated request bodies, attaches accepted contexts, emits AP-REP response
  headers, and supports borrowed, owned, file-name, configured-default, and environment-preferred keytab layers, with a compileable Axum Negotiate example; PAC
  parsing covers the PAC container, KERB_VALIDATION_INFO NDR, client info,
  UPN/DNS info, credentials info with AS-key decrypt helpers, S4U delegation
  info, device info, compressed and uncompressed client/device claims info,
  signature zeroing, authorization-data extraction, resource group SID
  expansion, gokrb5-style AD credential summaries, and AES service checksum
  verification, plus gated `TESTAD=1` keytab login, no-preauth login,
  user-domain service-ticket/PAC, and resource-trust service-ticket/PAC
  parity tests.
- `sspi-rs` is treated as a mature Negotiate/Kerberos collaboration or facade
  candidate.
- `krb5-rs` is not used as a base implementation because the published crate is
  currently pre-release and placeholder-sized.
- AGPL/LGPL Kerberos crates are excluded from the default/core implementation
  unless they are explicitly isolated behind non-default optional features.
- The first publishable API surface is the narrow `0.1.x` client preview
  described below.

## Supported 0.1.x Scope

The supported public preview surface is:

- password-backed client login;
- file keytab-backed client login;
- FILE, WRFILE, and MIT DIR credential-cache loading/saving;
- default config loading from `KRB5_CONFIG` or platform defaults;
- HTTP Negotiate/SPNEGO `Authorization` header generation through
  `NegotiateClient` and `BlockingNegotiateClient`;
- explicit typed rejection of unsupported credential stores.

Unsupported in `0.1.x`: API, KCM, KEYRING, and MSLSA credential stores; FAST;
PKINIT; system GSSAPI/SSPI facades; and full maintained Active Directory CI.

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

The live kpasswd integration test also requires the `test_kpasswd` workflow
input because it temporarily changes the Docker test principal password before
restoring it. Use `TEST_KPASSWD_ADDR`, `TEST_KPASSWD_PORT`, and
`TEST_KPASSWD_SADDR` when the password-change service or sender address differs
from the localhost defaults.

The Active Directory integration tests mirror gokrb5's `TESTAD=1` cases and
default to the gokrb5 lab addresses `192.168.88.100:88` and
`192.168.88.101:88`. Use `TEST_AD_USER_KDC_ADDR` and
`TEST_AD_RESOURCE_KDC_ADDR` to point them at another AD test environment.

## Distribution Direction

If the decision gate justifies a standalone crate, source, CI, and releases
will live on GitHub, while public Rust distribution will use crates.io.
The concrete release gate and crates.io cutover checklist are documented in
[`docs/publishing.md`](docs/publishing.md).
