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
  and exact DER round-trip expectations for `rasn-kerberos` and `picky-krb`.
- The first real modules are `keytab`, `krb5.conf`, `ccache`, `crypto`, and
  `service`: keytabs parse, serialize, and select keys against gokrb5 fixtures;
  config parsing covers libdefaults, realm host mappings, domain realm lookup,
  duration parsing, and configured KDC/KPassword server lookup; ccache parsing
  covers MIT file caches, opaque ticket bytes, server entry lookup, and exact
  fixture round-trips; crypto covers RFC3961 n-fold and RFC3962
  AES128/AES256-CTS-HMAC-SHA1-96 string-to-key, AES-CTS, checksums, and
  deterministic encrypted-message vectors; service validation covers
  gokrb5-generated AP-REQ fixtures, service-ticket decryption, authenticator
  decryption, client matching, ticket time checks, clock skew, replay, and
  address-required behavior, plus AP-REP mutual-auth reply generation and
  verification.
- `sspi-rs` is treated as a mature Negotiate/Kerberos collaboration or facade
  candidate.
- `krb5-rs` is not used as a base implementation because the published crate is
  currently pre-release and placeholder-sized.
- AGPL/LGPL Kerberos crates are excluded from the default/core implementation
  unless they are explicitly isolated behind non-default optional features.
- The crate is marked `publish = false` until the decision gate is complete.

Generate the compatibility report:

```sh
cargo run --bin rskrb5-compat-report
```

The report records the gokrb5 v8 test contract and the current support matrix
for candidate crates. Keep it current whenever a candidate or porting milestone
changes.

Run the local checks:

```sh
cargo fmt --check
cargo check --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --all-features --no-deps
cargo package --locked
prek run --all-files --stage pre-push
```

The GitHub workflow includes a manual Docker-backed integration job. Run it from
`workflow_dispatch` with the `integration` input once equivalent Rust
integration tests exist; it preserves the gokrb5-style `INTEGRATION=1`,
`TESTPRIVILEGED=1`, and optional `TESTAD=1` gates.

## Distribution Direction

If the decision gate justifies a standalone crate, source, CI, and releases
will live on GitHub, while public Rust distribution will use crates.io.
