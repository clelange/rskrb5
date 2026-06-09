# rskrb5

`rskrb5` is currently a compatibility spike for a future Rust port of
`gokrb5` v8.

The first milestone is not to duplicate existing permissively licensed ASN.1
or Kerberos crates. Instead, this repository evaluates whether existing crates
such as `rasn-kerberos`, `picky-krb`, and `sspi-rs` can satisfy the `gokrb5`
contract. If they cannot, this crate will become the missing high-level,
pure-Rust Kerberos library.

## Current Status

- `rasn-kerberos` and `picky-krb` are treated as dependency candidates for
  Kerberos DER/data types.
- The ASN.1 spike now checks 51 gokrb5 unit-test fixtures with separate decode
  and exact DER round-trip expectations for rasn-backed rskrb5 wrappers and
  `picky-krb`.
- The first real modules are `keytab`, `krb5.conf`, `ccache`, `crypto`,
  `client`, `kadmin`, `service`, and `pac`: keytabs parse, serialize, select keys, and generate
  password-derived ktutil-compatible entries from explicit principals or SPN-style names plus redacted metadata JSON against
  gokrb5 fixtures and load/save file-backed `KRB5_KTNAME` and
  `default_keytab_name` values;
  config parsing covers gokrb5-compatible libdefaults, `KRB5_CONFIG` path-list loading,
  realm host mappings, domain realm lookup, duration parsing, and configured KDC/KPassword server lookup; ccache parsing
  covers MIT file caches, `KRB5CCNAME` file cache-name helpers, opaque ticket bytes,
  server entry lookup, X-CACHECONF configuration entry read/write, redacted metadata JSON, and exact fixture round-trips; crypto covers RFC3961 n-fold, RFC3962
  AES128/AES256-CTS-HMAC-SHA1-96, RFC8009
  AES128/AES256-CTS-HMAC-SHA2, DES3-CBC-SHA1-KD, and RC4-HMAC string-to-key,
  KDF, checksums, and deterministic encrypted-message vectors; message wrappers
  preserve gokrb5 EncryptedData signed-kvno DER edge fixtures; kadmin covers
  ChangePasswdData builders, DER decode, exact fixture round-trip, KRB-PRIV payload building, and kpasswd request
  and reply frame parsing plus reply result handling and result-code checks; client AS/TGS exchange primitives
  cover deterministic TGT AS-REQ construction, KRB-ERROR preauthentication
  negotiation and surfacing, PA-ENC-TIMESTAMP encryption, assumed
  preauthentication, password/keytab TGT and explicit-service AS login helpers, PA-TGS-REQ
  service-ticket acquisition, a KDC transport boundary, Tokio TCP/UDP/auto
  KDC transport with response-too-big fallback and Docker auto-protocol AS/TGS
  coverage, configured/DNS SRV kpasswd transport, typed kpasswd request/reply/result exchanges, complete kpasswd request assembly with generated reply keys, kpasswd AP-REP validation, and a high-level Tokio password-change helper with initial kadmin/changepw ticket acquisition and credential update, `krb5.conf` configured KDC
  discovery, DNS SRV KDC discovery, AS-REP and TGS-REP encrypted-part decryption and validation,
  generic AP-REQ construction, cross-realm TGS referral following with cached
  and renewable referral TGT sessions, renewable AS/TGS request flags, explicit
  TGT/service-ticket renewal helpers, Docker MIT KDC AS/TGS login, TGT
  renewal, and gated kpasswd change/restore coverage across AES-SHA1, AES-SHA2, DES3, and RC4-HMAC, per-enctype
  keytab AS/TGS integration coverage, keytab file-name helpers, ccache credential export/write-back and
  file cache-name loading/saving, and a high-level
  Tokio client with password/keytab/ccache credential sources,
  credential attachment, file-name constructors/write-back, configuration validation, multi-realm TGT/session caching/removal,
  gokrb5-style refresh-window checks, explicit primary/realm TGT renewal, cancellable Tokio auto-renewal, affirm-login reuse,
  destroy semantics, service-ticket caching/lookup/removal, unusable-session pruning, redacted key debug output,
  zeroized key material, and gokrb5-shaped JSON
  session/cache snapshots plus structured diagnostics; service validation covers
  gokrb5-generated AP-REQ fixtures, service-ticket decryption, authenticator
  decryption, client matching, ticket time checks, clock skew, replay, and
  replay-cache aging, address-required behavior, file-name keytab validators,
  plus AP-REP mutual-auth reply generation and
  verification and verified ticket PAC extraction; SPNEGO/GSSAPI covers KRB5
  mech tokens, RFC4121 MIC and sealed/unsealed Wrap tokens, NegTokenInit/Resp,
  HTTP Negotiate headers with raw KRB5 token fallback, client AP-REQ initiator
  headers from TGS service tickets, AP-REP response verification, and service-side AP-REQ to AP-REP
  response flow;
  HTTP/Tower adapters cover
  generic `http` request helpers and service-side Tower middleware that
  challenges, validates, attaches accepted contexts, emits AP-REP response
  headers, and supports borrowed, owned, and file-name keytab layers, with a compileable Axum Negotiate example; PAC
  parsing covers the PAC container, KERB_VALIDATION_INFO NDR, client info,
  UPN/DNS info, credentials info with AS-key decrypt helpers, S4U delegation
  info, device info, compressed and uncompressed client/device claims info,
  signature zeroing, authorization-data extraction, resource group SID
  expansion, and AES service checksum verification.
- `sspi-rs` is treated as a mature Negotiate/Kerberos collaboration or facade
  candidate.
- `krb5-rs` is not used as a base implementation because the published crate is
  currently pre-release and placeholder-sized.
- AGPL/LGPL Kerberos crates are excluded from the default/core implementation
  unless they are explicitly isolated behind non-default optional features.
- The crate is marked `publish = false` until the decision gate is complete.

## Supported Scope During The Spike

The implemented preview scope is a pure-Rust Kerberos v5 client/service core
with file-backed keytab and ccache support, krb5.conf parsing, AES-SHA1,
AES-SHA2, DES3, and RC4-HMAC crypto, AS/TGS and kpasswd exchanges, AP-REQ
service validation, SPNEGO/GSSAPI HTTP helpers, Tower adapters, and PAC parsing
for the translated gokrb5 fixtures and Docker MIT KDC tests in this repository.

Known gaps before a public crates.io preview include non-FILE credential stores
such as DIR, API, KCM, and MSLSA; FAST, PKINIT, S4U2Self/S4U2Proxy client
flows; full Active Directory live-test coverage; system GSSAPI/SSPI facade
integration; and a declared stable API surface.

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
`workflow_dispatch` with the `integration` input to exercise the live MIT KDC AS
login test; it preserves the gokrb5-style `INTEGRATION=1`, `TESTPRIVILEGED=1`,
and optional `TESTAD=1` and `TEST_KPASSWD=1` gates.

The live kpasswd integration test also requires the `test_kpasswd` workflow
input because it temporarily changes the Docker test principal password before
restoring it. Use `TEST_KPASSWD_ADDR`, `TEST_KPASSWD_PORT`, and
`TEST_KPASSWD_SADDR` when the password-change service or sender address differs
from the localhost defaults.

## Distribution Direction

If the decision gate justifies a standalone crate, source, CI, and releases
will live on GitHub, while public Rust distribution will use crates.io.
The concrete release gate and crates.io cutover checklist are documented in
[`docs/publishing.md`](docs/publishing.md).
