# gokrb5 Parity Plan

This document tracks feature parity against `github.com/jcmturner/gokrb5/v8`
`v8.4.4`. The machine-readable source is
[`gokrb5-parity.toml`](gokrb5-parity.toml); update both files when a parity
area moves.

The parity target is the pure Go `gokrb5` client/service feature set: keytab,
ccache, krb5.conf, Kerberos crypto/messages, AS/TGS client flows, service-side
AP-REQ verification, GSSAPI/SPNEGO HTTP, PAC parsing, kpasswd, Docker MIT KDC
integration, and AD-gated behavior. Platform credential stores, PKINIT, full
FAST armor, and system GSSAPI/SSPI facades are useful future work but are not
required for `gokrb5/v8` parity.

## Status

| Area | Status | Next closure step |
|---|---|---|
| krb5.conf configuration | covered | Keep translated config tests current. |
| Keytab parsing, writing, and lookup | covered | Keep keytab fixture tests current. |
| Credential cache parsing, writing, and collection names | covered-with-gated-evidence | Keep privileged `kinit`/`kvno` ccache coverage green in Linux CI. |
| Kerberos cryptography | covered | Keep RFC/gokrb5 vectors current. |
| ASN.1 and Kerberos message wrappers | covered | Keep fixture matrix current. |
| RFC 3244 password change | covered-with-gated-evidence | Run `TEST_KPASSWD=1` in Linux CI before release. |
| AS/TGS client flows | covered-with-gated-evidence | Make the full Linux Docker MIT gate routine. |
| AP-REQ/AP-REP service validation | covered-with-gated-evidence | Confirm Linux Docker HTTP/SPNEGO service gate is stable. |
| GSSAPI, SPNEGO, and HTTP Negotiate tokens | partial | Add a ready-to-use HTTP client wrapper for 401 Negotiate retry flows. |
| PAC and NDR parsing | covered-needs-ad-evidence | Run `TESTAD=1` against a maintained AD lab. |
| Docker MIT KDC integration fixtures | needs-live-evidence | Use GitHub Actions or a Linux VM for DNS/privileged/full fixture evidence. |
| Active Directory integration | blocked-on-lab | Stand up or document reachable USER and RESOURCE AD realm endpoints. |
| Out-of-scope non-gokrb5 platform features | intentionally-out-of-scope | Keep typed unsupported-store errors and do not block parity on these. |

## Unproven Gates

These gates are the remaining proof points before claiming broad gokrb5 parity.
`required_for_release` means the gate should be green before the next breaking
preview release unless the release notes explicitly call it out as skipped.

| Gate | Status | Proves | Command or blocker | Next action |
|---|---|---|---|---|
| Full Linux Docker MIT integration | unproven | docker-mit, client, service, ccache | `scripts/run-gated-integration.sh run --test client_integration` | Run on GitHub Actions `workflow_dispatch` with integration enabled or on a Linux VM, then fix KDC, DNS-SRV, HTTP, referral, renewal, or ccache regressions. |
| Linux Docker MIT password-change integration | unproven | kadmin-kpasswd, client | `TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration` | Run the kpasswd gate on GitHub Actions or a Linux VM. |
| Linux Docker DNS-SRV KDC discovery | unproven | docker-mit, client | `TEST_DNS_KDC=1 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture` | Run with resolver mutation available and record whether SRV lookup reaches the Docker MIT KDC without configured KDC addresses. |
| Linux Docker privileged external ccache | unproven | ccache, client | `TESTPRIVILEGED=1 scripts/run-gated-integration.sh run --test client_integration` | Run with MIT `kinit` and `kvno` available and record FILE ccache import/export plus service-ticket lookup evidence. |
| Linux Docker HTTP SPNEGO service integration | unproven | service, gssapi-spnego, client | `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_spnego_header_authenticates_to_docker_http -- --nocapture` | Run the full HTTP/SPNEGO subset and record service acceptance plus replay rejection evidence. |
| Active Directory TESTAD integration | blocked-on-lab | active-directory, PAC, client, service | Needs maintained USER and RESOURCE AD realm endpoints. | Stand up or document the lab, then run `INTEGRATION=1 TESTAD=1 cargo test --all-features --test client_ad_integration`. |
| Ready-to-use HTTP Negotiate client wrapper | missing-api | gssapi-spnego, client | No wrapper API yet. | Add a request wrapper that retries 401 Negotiate responses and documents request body replay constraints. |

## Immediate Next Slices

1. Run the GitHub Actions `workflow_dispatch` Docker-backed integration job
   with DNS enabled. Record whether DNS-SRV, external `kinit`/`kvno`, HTTP,
   referrals, renewal, and ccache import/export all pass.
2. Run the same job with `test_kpasswd=true` and record password-change
   evidence.
3. Add the HTTP client wrapper: given a request and client/session state,
   detect `WWW-Authenticate: Negotiate`, acquire/build the AP-REQ token, retry
   with `Authorization`, and expose clear body replay constraints.
4. Create a maintained AD lab runbook or CI secret plan for `TESTAD=1`; do not
   claim AD parity until this gate runs green.

## Status Values

- `covered`: unit and fixture evidence is sufficient for this parity area.
- `covered-with-gated-evidence`: implemented and unit-covered, but release
  confidence depends on keeping a live Docker or privileged gate green.
- `covered-needs-ad-evidence`: implemented and unit-covered, but AD parity is
  not proven until `TESTAD=1` runs against a maintained lab.
- `partial`: meaningful implementation exists, but a user-facing gokrb5 parity
  behavior is still missing.
- `needs-live-evidence`: implementation may exist, but current proof is not
  broad enough for a release parity claim.
- `blocked-on-lab`: code exists, but external infrastructure is required.
- `unproven`: the test, fixture, or implementation target is known, but the
  release-blocking proof has not been captured on the required platform.
- `missing-api`: supporting pieces exist, but the user-facing parity API is not
  implemented yet.
- `intentionally-out-of-scope`: not required for gokrb5/v8 parity.
