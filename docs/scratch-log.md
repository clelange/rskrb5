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
