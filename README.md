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

## Distribution Direction

If the decision gate justifies a standalone crate, source, CI, and releases
will live on GitHub, while public Rust distribution will use crates.io.
