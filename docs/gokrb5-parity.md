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
| RFC 3244 password change | covered-with-gated-evidence | Keep `TEST_KPASSWD=1` green in Linux CI. |
| AS/TGS client flows | covered-with-gated-evidence | Keep the full Linux Docker MIT gate green. |
| AP-REQ/AP-REP service validation | covered-with-gated-evidence | Keep Linux Docker HTTP/SPNEGO service coverage green. |
| GSSAPI, SPNEGO, and HTTP Negotiate tokens | covered-with-gated-evidence | Keep HTTP wrapper tests and Docker SPNEGO integration green. |
| PAC and NDR parsing | covered-needs-ad-evidence | Run `TESTAD=1` against a maintained AD lab. |
| Docker MIT KDC integration fixtures | covered-with-gated-evidence | Keep workflow-dispatched Docker-backed integration green. |
| Active Directory integration | blocked-on-lab | Deferred for 0.2.0 until reachable USER/RESOURCE AD endpoints are available; keep the dry-run evidence green and do not claim AD parity. |
| Out-of-scope non-gokrb5 platform features | intentionally-out-of-scope | Keep typed unsupported-store errors and do not block parity on these. |

## Parity Gates

These gates are the release and parity proof points for gokrb5 behavior.
`required_for_release` means the gate should stay green before the next breaking
preview release unless the release notes explicitly call it out as skipped.

| Gate | Status | Proves | Command or blocker | Next action |
|---|---|---|---|---|
| Full Linux Docker MIT integration | proven | docker-mit, client, service, ccache | `scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed 40 Docker MIT `client_integration` tests on `ubuntu-latest`; keep this gate green. |
| Linux Docker MIT password-change integration | proven | kadmin-kpasswd, client | `TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed `docker_mit_kdc_tokio_client_change_password`; keep this gate green. |
| Linux Docker DNS-SRV KDC discovery | proven | docker-mit, client | `TEST_DNS_KDC=1 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture` | GitHub Actions run `28073249506` passed `docker_mit_kdc_dns_srv_as_login`; keep this gate green. |
| Linux Docker privileged external ccache | proven | ccache, client | `TESTPRIVILEGED=1 scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed external `kinit` and `kvno` ccache tests; keep this gate green. |
| Linux Docker HTTP SPNEGO service integration | proven | service, gssapi-spnego, client | `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_spnego_header_authenticates_to_docker_http -- --nocapture` | GitHub Actions run `28073249506` passed HTTP SPNEGO, raw KRB5 Negotiate, and replay rejection tests; keep this gate green. |
| Active Directory TESTAD integration | blocked-on-lab | active-directory, PAC, client, service | GitHub Actions run [`28119806826`](https://github.com/clelange/rskrb5/actions/runs/28119806826) passed the hosted keytab-secret dry-run; strict run [`28117082548`](https://github.com/clelange/rskrb5/actions/runs/28117082548) reached hosted `ubuntu-latest` and decoded the four keytab secrets before failing because the endpoint secrets are absent. | Deferred for 0.2.0; revisit after reachable `TEST_AD_*_ADDR` secrets exist, then run `scripts/check-github-ad-gate.py --dispatch`. |
| Ready-to-use HTTP Negotiate client wrapper | proven | gssapi-spnego, client | `cargo test --all-features --test http` | Async `send_with_negotiate` and blocking `send_with_blocking_negotiate` retry 401 Negotiate responses through replayable request factories; keep this gate green. |

## Deferred Blockers

- Active Directory parity remains blocked on reachable endpoint secrets:
  `TEST_AD_USER_KDC_ADDR`, `TEST_AD_RESOURCE_KDC_ADDR`,
  `TEST_AD_USER_ADMIN_ADDR`, and `TEST_AD_RESOURCE_ADMIN_ADDR`. This is
  recorded but explicitly not a `0.2.0` release blocker.
- The current acceptable 0.2.0 evidence is the green hosted keytab-secret
  dry-run plus static AD keytab fixture coverage. These do not prove Windows AD
  PAC parity.

## Immediate Next Slices

1. Keep the workflow-dispatched Docker MIT gate green with `integration=true`,
   `test_kpasswd=true`, and `test_ad=false` before the next release.
2. Prepare release notes for the next breaking preview with the new API surface
   and the explicitly deferred AD gate called out.
3. Use [`samba-ad-feasibility.md`](samba-ad-feasibility.md) as a backup spike
   only; do not treat Samba results as Windows AD parity evidence.

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
- `proven`: the named gate has been captured green on the required platform and
  should stay green before release.
- `unproven`: the test, fixture, or implementation target is known, but the
  release-blocking proof has not been captured on the required platform.
- `missing-api`: supporting pieces exist, but the user-facing parity API is not
  implemented yet.
- `intentionally-out-of-scope`: not required for gokrb5/v8 parity.
