# Release Notes

## Unreleased 0.2.0 Preview

`0.2.0` is the next breaking pre-`1.0` preview after the published `0.1`
release. The release goal is a smaller, more maintainable Rust API while
keeping Kerberos wire formats, cryptographic behavior, and fixture parity
compatibility-sensitive.

### Breaking API Changes

- The crate version is now `0.2.0`; breaking Rust API changes should ship as a
  new minor preview release rather than a `0.1.x` patch.
- `rskrb5::kadmin` no longer exposes temporary gokrb5-named aliases:
  `ChangePasswdData::unmarshal`, `ChangePasswdData::marshal`,
  `Request::unmarshal`, `Request::marshal`, `Reply::unmarshal`,
  `Reply::marshal`, `Reply::decrypt`, `Reply::result_code`,
  `Reply::result_text`, `change_passwd_msg`, `change_passwd_msg_with_options`,
  and `change_passwd_msg_with_confounders`.
- Use the canonical password-change API instead:
  `ChangePasswdData::decode_der`, `ChangePasswdData::encode_der`,
  `Request::parse`, `Request::encode`, `Reply::parse`, `Reply::encode`,
  `Reply::decrypt_result`, `build_change_password_message`, and
  `build_change_password_message_with_confounders`.
- `rskrb5::crypto::AesEtype` has been removed. Use
  `rskrb5::crypto::KerberosEtype`; it covers AES-SHA1, AES-SHA2, DES3, and
  RC4-HMAC dispatch.

### Refactor Notes

- Client principal parsing, request options, and Negotiate wrappers are split
  into private `client` child modules and re-exported intentionally.
- SPNEGO object identifiers and the PAC byte reader are split into private
  helper modules.
- Principal parsing tests are split out of the large client test file.

### Package Hygiene

- The lockfile moves the yanked transitive `crypto-bigint 0.7.3` dependency to
  `0.7.5`.
- `picky-krb` remains evaluation-only and is not part of the supported runtime
  surface.

### Release Evidence

Current local evidence for the `0.2.0` preview branch, recorded on
2026-06-23:

- `cargo fmt --check`
- `cargo check --no-default-features`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo doc --all-features --no-deps`
- `cargo run --no-default-features --features evaluation --bin rskrb5-compat-report`
  matches [`compatibility-report.md`](compatibility-report.md)
- `cargo package --locked --allow-dirty`
- `prek run --all-files --stage pre-push`

Integration evidence:

- Full local Docker MIT run attempted with
  `scripts/run-gated-integration.sh run --test client_integration`; this local
  direct-container-IP run failed with transport timeouts to
  `192.168.215.x:88` endpoints.
- Focused forwarded-port Docker MIT configured-KDC AS login passed with
  `RSKRB5_DIRECT_CONTAINER_IP=0 TEST_DNS_KDC=0 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_configured_kdc_as_login -- --nocapture`.
- Focused forwarded-port kpasswd coverage passed with
  `TEST_KPASSWD=1 RSKRB5_DIRECT_CONTAINER_IP=0 TEST_DNS_KDC=0 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_tokio_client_change_password -- --nocapture`.
- `TESTAD=1` was not run in this pass because no reachable maintained AD lab
  was configured.

Before publishing, rerun the release preflight in
[`publishing.md`](publishing.md), regenerate
[`compatibility-report.md`](compatibility-report.md), and record the final
Docker/AD gate results in the GitHub release notes.
