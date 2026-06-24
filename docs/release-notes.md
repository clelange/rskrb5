# Release Notes

## Unreleased

- Added a dedicated Active Directory integration runbook and strict
  `TESTAD_REQUIRED=1` mode so future AD parity evidence cannot pass by
  soft-skipping unreachable lab endpoints.
- Added AD keytab override variables for lab-specific keytab files, hex
  secrets, or base64 secrets.
- Added `scripts/check-ad-integration-env.py` to preflight strict AD gate
  environment, reachability, and keytab secret shape.

## 0.2.0 Preview - 2026-06-24

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
- `rskrb5::http` now exposes transport-agnostic 401 retry wrappers:
  `send_with_negotiate`, `send_with_negotiate_options`,
  `send_with_blocking_negotiate`, and
  `send_with_blocking_negotiate_options`. These APIs require a replayable
  request factory so request bodies are rebuilt explicitly when a server
  responds with `WWW-Authenticate: Negotiate`.

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

Final local evidence for `0.2.0`, recorded on 2026-06-24:

- `cargo fmt --check`
- `cargo check --no-default-features`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo doc --all-features --no-deps`
- `cargo run --no-default-features --features evaluation --bin rskrb5-compat-report`
  matches [`compatibility-report.md`](compatibility-report.md)
- `cargo package --locked`
- `cargo publish --locked --dry-run`
- `prek run --all-files --stage pre-push`

Integration evidence:

- GitHub Actions workflow-dispatch run
  [`28073249506`](https://github.com/clelange/rskrb5/actions/runs/28073249506)
  passed on the HTTP-wrapper implementation commit
  `78ab19ebc10ecd7e33244490097742276af24d75`; later release-prep commits
  changed docs and package metadata only.
- The Docker-backed integration job ran on `ubuntu-latest` with
  `INTEGRATION=1`, `TESTPRIVILEGED=1`, `TEST_KPASSWD=1`, and `TEST_DNS_KDC=1`.
- `tests/client_integration.rs` passed 40 Docker MIT tests, including DNS-SRV
  KDC discovery, external `kinit`/`kvno` ccache import, HTTP SPNEGO/raw KRB5
  Negotiate acceptance, replay rejection, referrals, renewal, cached service
  tickets, and kpasswd password change.
- `TESTAD=1` remains skipped for this preview because no reachable maintained
  AD lab is configured. Do not claim full AD parity until the
  `active-directory-testad` parity gate is green.
