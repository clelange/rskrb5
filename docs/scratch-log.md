# rskrb5 Scratch Log

## 2026-06-14

- Decision: allow API changes before 1.0, but keep the first refactor narrow so review can separate structural movement from new SPNEGO/HTTP behavior.
- Decision: extract Tokio KDC transport and discovery into a `client` child module. The child module can call parent-private builders/processors, which avoids making internal exchange helpers public just for refactoring.
- Trade-off: keep runtime-neutral `KdcTransport` in `client.rs`; it is part of the request/response unit-test boundary, not the Tokio network transport being extracted.
- Review note: preserve existing local edit in `tests/spnego.rs`; it aligns SPNEGO fixture assertions with rskrb5 AP-REQ helpers.
- Decision: keep `spnego_header*` and `authorization_header*` as convenience wrappers, while adding context-returning methods as the canonical path for AP-REP verification.
- Decision: HTTP response verification scans every `WWW-Authenticate` value and accepts comma-separated challenges. The parser is intentionally limited to finding a `Negotiate` challenge; it does not try to fully parse every auth scheme's parameter grammar.
- Trade-off: tests adjust only cached-session metadata to current time when exercising `TokioClient`'s cache path; the DER ticket fixture remains unchanged for SPNEGO token compatibility checks.
- Review fix: focused HTTP tests initially missed the cached service ticket because the fixture metadata is future-dated relative to the current test clock; fixed by making the cache metadata current in that one test.
- Decision: add a transport-agnostic HTTP Negotiate client classifier instead of binding retry logic to a concrete HTTP client. Callers can keep ownership of request cloning, body replay policy, and redirect handling.
- Trade-off: classify malformed or unexpected response tokens into an enum variant instead of returning early with an error, so client response handling can stay exhaustive and single-pass.
- Verification: `cargo fmt --check`, `cargo check --no-default-features`, `cargo check`, `cargo check --no-default-features --features http`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and the generated compatibility-report diff all pass.
- Validation note: local Docker MIT integration passes with `INTEGRATION=1`; `TESTPRIVILEGED=1` also passes when Homebrew krb5 is on PATH for `kvno` and macOS uses direct container-IP routing to avoid address-bound ticket failures through port forwarding.
- Review fix: privileged external `kvno` coverage exposed MIT ccache service tickets with name type `1` for `HTTP/host` entries. Preserve ccache parsing as-is, but normalize high-level cached service-ticket returns to the caller's resolved service principal.
- Blocked gate: `TESTAD=1` still times out against the default AD lab endpoint `192.168.88.100:88` from this network; both `nc` and the Rust tests confirm the USER realm KDC is unreachable.
- Blocked gate: local DNS-SRV validation could start the gokrb5 DNS container, but direct `dig` queries returned `REFUSED` or timed out under OrbStack instead of serving the expected test zone.
- Review fix: `TEST_KPASSWD=1` exposed that successful kpasswd replies encrypt AP-REP with the kadmin/changepw ticket session key, then may encrypt the KRB-PRIV result with an AP-REP server subkey. The high-level client now verifies AP-REP with the ticket session key and decrypts the result with the AP-REP subkey when present, falling back to the request subkey.
- Verification: focused kpasswd unit coverage passes, the live Docker MIT `TEST_KPASSWD=1` change/restore test now passes over TCP, and a follow-up AS-login sanity check confirms `testuser1` is restored to `passwordvalue`.

## 2026-06-16

- Decision: extract the Docker-backed gokrb5 fixture startup from the GitHub workflow into `scripts/run-gated-integration.sh` so local and CI validation share the same container names, ports, generated env, and cleanup path.
- Trade-off: on Darwin, default to direct Docker container IPs and skip resolver mutation unless explicitly requested. This keeps no-sudo local runs useful for `INTEGRATION=1`, `TESTPRIVILEGED=1`, HTTP, referral, old/latest/short KDCs, and focused kpasswd validation, while leaving DNS-SRV enabled by default on Linux/CI.
- Review fix: the gokrb5 DNS image allows queries only from localhost and selected Docker bridge CIDRs; OrbStack uses `192.168.215.0/24`, so local direct queries were refused. The runner now relaxes the fixture `allow-query` ACL and records the DNS container IP in `target/gated-integration.env` when direct-container mode is active.
- Verification: direct `dig @"$DNS_IP"` SRV/A queries now succeed locally, `scripts/run-gated-integration.sh test --test client_integration` passes with DNS skipped, and focused `TEST_KPASSWD=1` password-change validation passes through the runner.
- Decision: treat upstream `gokrb5/v8/kadmin` as kpasswd message parity rather than a broad kadm5 admin-client surface; upstream exposes password-change message construction/parsing, not principal database RPCs.
- Decision: add the next kadmin slice as a module-owned request-frame builder that accepts a caller-built AP-REQ and returns the typed request, DER frame, and reply key. This keeps service-ticket/AP-REQ construction in `client` while moving RFC 3244 frame assembly and encrypted `ChangePasswdData` ownership into `kadmin`.
- Trade-off: keep random reply-key and confounder generation in `client` for now because that code already has the service-ticket session context. The new `kadmin` API is deterministic and testable with explicit confounders.
- Decision: add random-confounder `kadmin` convenience builders for KRB-PRIV and full kpasswd request framing. `client` still owns reply-key and AP-REQ confounder generation, but generated KRB-PRIV request encryption now belongs to `kadmin`.
- Trade-off: do not add a full service-ticket `ChangePasswdMsg` clone in `kadmin` yet; doing so would either pull client session types into `kadmin` or duplicate AP-REQ authenticator construction. Keep that seam private until the client/session modules are slimmer.

## 2026-06-17

- Decision: extract client-side kpasswd request construction, AP-REP verification, and Tokio password-change methods into `src/client/kpasswd.rs` while re-exporting the public API from `rskrb5::client`. This keeps compatibility paths stable and reduces the main `client.rs` surface before adding a fuller gokrb5-shaped password-change message API.
- Trade-off: keep the child module private and let it use parent-private AP-REQ and time helpers. That avoids widening internal helper visibility only for refactoring.
- Review fix: workflow-dispatched Docker integration exposed that the DNS ACL relaxation sent `SIGHUP` to a foreground `named` process, killing the gokrb5 DNS fixture. The runner now reloads BIND through `rndc reconfig` and probes both direct fixture DNS and the configured system resolver before running DNS-dependent Rust tests.
- Trade-off: keep application DNS discovery tied to the OS resolver for parity; harden the fixture runner instead of adding test-only resolver injection to `TokioKdcTransport`.
- Verification: `bash -n scripts/run-gated-integration.sh` passes, local Docker fixture startup leaves `dns` running after ACL relaxation, direct fixture DNS answers SRV/A records via the generated `DNS_IP`, focused `TEST_KPASSWD=1` password-change integration passes with resolver mutation disabled, and DNS-enabled startup passes the new direct readiness probe.
- Review fix: GitHub Actions preserved successful DNS setup within the `start` step but the following `test` step still resolved through the default runner DNS. The runner now reapplies and verifies resolver configuration inside `scripts/run-gated-integration.sh test` immediately before invoking `cargo test`.
- Review fix: shell-level `dig` verification can pass while `hickory-resolver` still observes the hosted runner's default resolver behavior. The Tokio DNS SRV path now honors `RSKRB5_DNS_SERVER=ip[:port]` when set by the gated runner, while normal client behavior continues to use system resolver configuration.
- Trade-off: when an explicit DNS server override is active, DNS-SRV endpoint construction also resolves SRV target hostnames to IP literals through that resolver. This keeps Docker fixture connections off the host resolver without changing default production behavior.
- Review fix: live HTTP Negotiate tests now connect to `TEST_HTTP_ADDR` while preserving the `TEST_HTTP_URL` host header, so HTTP validation no longer depends on host DNS for the socket address.
- Verification: with resolver mutation disabled, the local gated Docker slice now passes the DNS-SRV AS-login test plus both raw Kerberos and SPNEGO HTTP authentication tests.
- Review fix: the compatibility report generator's evaluation-only feature set exposed a Tokio-only kpasswd import warning; moved that import behind the Tokio feature gate.

## 2026-06-20

- Decision: add `TokioClient::change_password_for` and
  `TokioClient::change_password_for_with_options` to support explicit target
  principals in kadmin change flows while preserving existing
  `change_password*` default-target behavior.
- Decision: update in-place password credential rotation only when target matches the
  configured client principal; changing another principal keeps login credentials
  unchanged.
- Trade-off: keep service-ticket acquisition logic and error mapping inside `client`
  and avoid new generic helpers; only target principal construction and request
  intent were added in `kpasswd`.
- Verification: added a focused Tokio unit test that asserts target principal appears in
  the encrypted `ChangePasswdData` payload and that kpasswd responses are accepted
  through the new target-specific API.
- Decision: when constructing `ChangePasswdData`, keep `targ_name`/`targ_realm`
  unset for self-password changes, and set explicit target fields only for
  `change_password_for` calls targeting another principal.
- Decision: explicit-target password changes must still authenticate AS/requests as
  `self.client` and only vary the encrypted `ChangePasswdData` target metadata;
  this avoids reusing long-term credentials as the `target` principal.
- Trade-off: this behavior change fixes a latent credential flow bug but preserves the
  existing “password rotation only for self target” contract for simplicity.
- Review fix: initial implementation used `target` as AS-login client principal and
  always encoded `target` in `ChangePasswdData`, which caused explicit-target change
  to mutate the local principal and wrong request contents on subsequent self-change
  attempts. Tests now cover both regressions: explicit target payload fields and the
  non-rotation path.

## 2026-06-22

- Decision: mirror `TokioClient` password-change methods on `NegotiateClient` and
  `BlockingNegotiateClient` as thin pass-throughs (`change_password*` methods).
- Trade-off: this expands the high-level HTTP wrapper API but keeps behavior
  centralized in `client/kpasswd.rs`, avoiding duplicated logic and preserving
  existing kadmin request semantics.

## 2026-06-23

- Decision: add focused wrapper-path tests for `NegotiateClient` and
  `BlockingNegotiateClient` password-change methods before advancing to broader
  HTTP SPNEGO changes, so the preview surface extension stays regression-safe.
- Trade-off: the tests reuse existing synthetic TGT/TGS fixtures and local TCP
  listeners to validate `change_password*` path behavior, avoiding a dependency
  on additional integration fixtures.
- Review fix: updated README, crate docs, and release-surface notes to make
  `change_password*` wrapper methods part of the documented `0.1.x` preview scope.

## 2026-06-24

- Decision: complete `kadmin` compatibility for gokrb5-style message construction by
  adding `ChangePasswdMessageOptions`, full message builders, and aliases
  (`unmarshal`, `marshal`, `change_passwd_msg`,
  `change_passwd_msg_with_confounders`, etc.) in `src/kadmin.rs`.
- Decision: keep API-level compatibility for 9-argument constructors despite clippy
  warnings pressure; compatibility shape is preserved while attaching narrow local
  `#[allow(clippy::too_many_arguments)]` attributes until API stability milestones
  permit a safe signature refactor.
- Trade-off: `tests/kadmin.rs` now contains explicit helpers for `KerberosTime` and
  principal/key conversions to avoid brittle fixture assumptions in assertions and to
  keep test intent readable.
- Review fix: aligned explicit confounder fixture sizes to the negotiated etype confounder
  length to avoid `invalid confounder length` failures.
- Verification: `cargo fmt --check`, `cargo check --no-default-features`, `cargo check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`,
  and compatibility-report regeneration diff are all passing with 25/25 focused kadmin tests.

## 2026-06-20 (follow-up)

- Decision: keep privileged integration behavior robust across hosts by adding a runtime
  availability gate for the host `kinit` and `kvno` binaries before running external-ccache
  and kvno-specific Docker KDC tests.
- Trade-off: environments without optional Kerberos binaries now skip those specific tests
  with explicit reason logging, rather than failing the integration run before execution.
- Review fix: dedicated `privileged_kvno_integration_enabled()` helper now wraps the existing
  privileged gate and gates only the kvno-dependent tests in `tests/client_integration.rs`.
- Verification: `cargo fmt --check`, `cargo check --no-default-features`, `cargo check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features`
  all pass.

- Decision: keep `kadmin` API parity narrow for gokrb5-v8 by adding compatible reply
  accessors in `src/kadmin.rs`: `Reply::result_code` and `Reply::result_text`,
  matching `ResultCode`/`Result` intent while preserving existing `Option`-style semantics.
- Trade-off: these helpers intentionally return `None` for success replies (`KRB-REP`) and
  only populate on error replies (`KRB-ERROR`), which avoids implicit error defaults and keeps
  behavior explicit for callers.
- Review fix: added tests in `tests/kadmin.rs` for both populated-failure and
  success-`None` helper behavior so future parser regressions are caught directly.
- Verification: ran full local validation (`cargo fmt --check`, `cargo check
  --no-default-features`, `cargo check`, `cargo check --all-features`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-features`) and compatibility-report diff; all passed.

## 2026-06-20 (follow-up, AD hardening)

- Decision: harden `TESTAD=1` integration entry by adding explicit TCP reachability
  checks for the configured AD test KDC endpoints in `tests/client_ad_integration.rs`.
- Trade-off: AD suites now skip early with clear logs when either realm KDC is unreachable,
  rather than failing later as `KdcEndpointFailures` after transport timeouts.
- Review fix: centralized AD address derivation into helpers (`ad_user_kdc_addr`, `ad_resource_kdc_addr`,
  `ad_user_admin_addr`, `ad_resource_admin_addr`) so tests and preflight checks share defaults
  and user-overridden env values.
- Verification: `cargo fmt --all`, `cargo check --no-default-features`,
  `cargo check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-features`, and dedicated `cargo test --all-features --test client_ad_integration`
  all pass.

## 2026-06-25

- Decision: complete the narrow `kadmin::Reply` marshal/encoding parity slice for
  gokrb5 compatibility by adding `Reply::encode` and `Reply::marshal` alias.
- Trade-off: implement encode by reusing existing typed message encoders (`ap_rep`,
  `krb_error`, `krb_priv`) and mapping module-specific errors through local
  conversion helpers, avoiding a new generic serializer abstraction.
- Decision: fail inconsistent reply states with a dedicated
  `Error::InvalidErrorReplyPayload` when a KRB-ERROR reply also carries AP-REP/KRB-PRIV
  payload fields.
- Review fix: fixed compile-time scoping (`encode_krb_error`, `encode_ap_rep`) and mapped
  `encode_krb_error` failures through `krb_error_error`.
- Verification: `cargo fmt --check`, `cargo check --no-default-features`,
  `cargo check`, `cargo check --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all-features`, compatibility-report diff, and
  `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login`
  all pass.

## 2026-06-26

- Decision: add focused negative parity tests for `Reply::encode` invariants:
  mixed KRB-ERROR + AP-REP payloads and missing required reply fields.
- Trade-off: keep these as unit tests in `tests/kadmin.rs` only; no transport-level
  or integration tests were added because the invariants are pure serialization state
  checks and already covered by existing integration flows.
- Review fix: confirmed `tests/kadmin.rs` coverage expanded to 32 tests and no
  regressions; all test suites and compatibility-report diff still pass.
