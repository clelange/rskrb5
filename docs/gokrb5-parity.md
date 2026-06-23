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
- `intentionally-out-of-scope`: not required for gokrb5/v8 parity.
