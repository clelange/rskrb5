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

Before publishing, rerun the release preflight in
[`publishing.md`](publishing.md), regenerate
[`compatibility-report.md`](compatibility-report.md), and record Docker/AD gate
results in the GitHub release notes.
