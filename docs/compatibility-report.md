# rskrb5 Compatibility Spike

This report is generated from `rskrb5::evaluation` and captures the decision gate before implementing a standalone Kerberos library.

## rasn-kerberos

- License: `MIT OR Apache-2.0`
- Recommendation: Use as a dependency candidate for ASN.1 types, not as a replacement.

| Area | Support | Note |
|---|---:|---|
| Kerberos ASN.1 data types | yes | Provides RFC 4120 types and DER encode/decode through rasn. |
| Message wrappers / exact gokrb5 DER vectors | partial | Promising; must be verified against gokrb5's full DER fixture set. |
| Client AS/TGS exchange | no | Data types only; no authentication behavior. |
| Service AP-REQ verification | no | No replay cache, decryption, or verifier behavior. |
| SPNEGO/GSSAPI | no | No HTTP Negotiate or GSSAPI context implementation. |
| Keytab / ccache / krb5.conf / PAC | no | Out of scope for this crate. |

## picky-krb

- License: `MIT OR Apache-2.0`
- Recommendation: Evaluate as an ASN.1/PAC dependency candidate alongside rasn-kerberos.

| Area | Support | Note |
|---|---:|---|
| Kerberos ASN.1 data types | yes | Provides Kerberos DER structures and message types. |
| Message wrappers / exact gokrb5 DER vectors | partial | Has richer Microsoft/Kerberos structs than rasn-kerberos; requires fixture parity checks. |
| PAC | partial | Parses PAC container data, but not the full gokrb5 PAC/NDR surface by itself. |
| Client AS/TGS exchange | no | No complete client flow. |
| Service AP-REQ verification | no | No complete verifier/replay-cache flow. |
| Keytab / ccache / krb5.conf | no | Out of scope for this crate. |

## sspi-rs

- License: `MIT OR Apache-2.0`
- Recommendation: Run deeper spike before deciding between contribution, facade, or new crate.

| Area | Support | Note |
|---|---:|---|
| Negotiate/Kerberos authentication | partial | Mature SSPI-shaped implementation; useful for Negotiate flows. |
| Public API shape | partial | SSPI API is not a gokrb5-style Kerberos client/service API. |
| Keytab / ccache / krb5.conf | partial | Kerberos config exists, but gokrb5 parity needs direct verification. |
| PAC / Microsoft extensions | partial | Strong Microsoft protocol coverage; exact PAC contract still needs tests. |
| Dependency direction | partial | Potential dependency or collaboration target rather than a full replacement. |

## kerberos-parser

- License: `MIT OR Apache-2.0`
- Recommendation: Useful as a parser reference, not as the base implementation.

| Area | Support | Note |
|---|---:|---|
| Kerberos ASN.1 parsing | partial | Parses Kerberos protocol structures; not a typed DER encode/decode layer. |
| Client AS/TGS exchange | no | Parser crate only; no authentication behavior. |
| Service AP-REQ verification | no | No replay cache, decryption, keytab, or verifier behavior. |
| SPNEGO/GSSAPI | no | No HTTP Negotiate or GSSAPI context implementation. |

## krb5-rs

- License: `Apache-2.0`
- Recommendation: Do not use as the base implementation at this time.

| Area | Support | Note |
|---|---:|---|
| Published implementation | excluded | Published 0.1.0 package is placeholder-sized and README marks core RFCs as planned. |
| Client AS/TGS exchange | no | No implemented client module in the published crate. |
| GSSAPI/SPNEGO | no | No implemented GSSAPI module in the published crate. |

## kerbeiros/kerberos_*

- License: `AGPL-3.0`
- Recommendation: Exclude from the default/core implementation due to AGPL licensing.

| Area | Support | Note |
|---|---:|---|
| Keytab / ccache / crypto / ASN.1 | excluded | Relevant primitives exist, but AGPL-3.0 licensing excludes core use. |
| Client AS/TGS exchange | excluded | Do not depend on these crates in the core implementation without explicit isolation. |

## kenobi

- License: `MIT`
- Recommendation: Consider only as an optional/reference Negotiate client path.

| Area | Support | Note |
|---|---:|---|
| HTTP Negotiate client | partial | Cross-platform Negotiate client, but not a pure-Rust gokrb5-style Kerberos core. |
| System dependency | partial | Uses platform-specific GSSAPI/SSPI behavior rather than portable Kerberos primitives. |
| Service AP-REQ verification | no | Client-focused; does not satisfy gokrb5 service validation or replay-cache contract. |

## axum-negotiate-layer/axum-negotiate

- License: `MIT / LGPL-3.0-or-later by crate`
- Recommendation: Treat as optional web integration references, not core Kerberos dependencies.

| Area | Support | Note |
|---|---:|---|
| SPNEGO HTTP middleware | partial | Useful integration reference, but middleware is not the Kerberos implementation. |
| License posture | partial | axum-negotiate-layer is MIT; axum-negotiate is LGPL and excluded from core use. |
| Keytab / ccache / krb5.conf / PAC | no | Out of scope for HTTP middleware crates. |

## cross-krb5/libgssapi

- License: `MIT`
- Recommendation: Useful optional interop/reference layer, not the pure-Rust core.

| Area | Support | Note |
|---|---:|---|
| GSSAPI/SPNEGO | yes | Provides safe access to system GSSAPI/SSPI behavior. |
| Pure Rust / no system dependency | no | Depends on system Kerberos/GSSAPI behavior, unlike gokrb5. |
| Keytab / ccache / krb5.conf primitives | partial | Available through system APIs, not as portable pure Rust primitives. |

## Decision

Create a new `rskrb5` implementation only if `sspi-rs` plus permissively licensed ASN.1 crates cannot satisfy gokrb5 v8 parity without an awkward API facade. The immediate implementation work is to translate gokrb5 fixture tests and keep measuring candidates against those tests.
