# rskrb5 Compatibility Spike

This report is generated from `rskrb5::evaluation` and captures the dependency decision gate and ongoing candidate matrix for a gokrb5-equivalent Rust implementation.

## gokrb5 v8 Contract

| Area | gokrb5 tests | Gate | Porting note |
|---|---|---|---|
| ASN.1 / DER messages | messages/*_test.go, types/*_test.go, kadmin/*_test.go | unit | Translate fixture round-trip tests first; reuse permissive ASN.1 crates where they pass. |
| Kerberos crypto vectors | crypto/**/*_test.go | unit | Use gokrb5/RFC vectors for string-to-key, checksum, encrypt, decrypt, and key usage behavior. |
| keytab | keytab/keytab_test.go | unit | Parse/write keytabs and select keys by service principal, realm, kvno, and enctype. |
| ccache | credentials/ccache_test.go, credentials/ccache_integration_test.go | unit, INTEGRATION=1 | Implement MIT file ccache parsing/writing plus KDC-issued credential capture. |
| krb5.conf and host config | config/*_test.go | unit | Preserve gokrb5 parsing semantics, libdefaults, realm lookup, DNS flags, and host mappings. |
| AS/TGS client flows | client/*_test.go | unit, INTEGRATION=1, TESTAD=1 | Cover password/keytab login, TCP/UDP KDC transport, referrals, DNS KDC lookup, renewal, and service tickets. |
| AP-REQ/AP-REP service validation | service/*_test.go, messages/Ticket_test.go | unit, INTEGRATION=1 | Decrypt tickets, validate authenticators, enforce clock skew, provide replay cache hooks, and build/verify AP-REP mutual-auth replies. |
| GSSAPI/SPNEGO HTTP | gssapi/*_test.go, spnego/*_test.go | unit, INTEGRATION=1 | Implement tokens, wrap/MIC behavior, HTTP Negotiate helpers, and Tower/Axum adapters. |
| PAC / NDR | pac/*_test.go, messages/Ticket_test.go | unit, TESTAD=1 | Parse PAC buffers, NDR validation info, claims, UPN/DNS info, and checksum verification. |
| Docker KDC integration | client/*_integration_test.go, credentials/*_integration_test.go, spnego/http_test.go | INTEGRATION=1, TESTPRIVILEGED=1, TESTAD=1 | Reuse gokrb5 MIT KDC, DNS, short-ticket, referral-domain, HTTP, and AD gates where possible. |

## Candidate Decision Matrix

| Candidate | asn1 | crypto | keytab | ccache | conf | client | service | spnego | pac | docker |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rasn-kerberos | partial | no | no | no | no | no | no | no | no | no |
| picky-krb | partial | no | no | no | no | no | no | no | partial | no |
| sspi-rs | partial | partial | partial | partial | partial | partial | partial | partial | partial | partial |
| kerberos-parser | partial | no | no | no | no | no | no | no | no | no |
| krb5-rs | no | no | no | no | no | no | no | no | no | no |
| kerbeiros/kerberos_* | excluded | excluded | excluded | excluded | no | excluded | no | no | no | no |
| kenobi | no | no | no | no | no | partial | no | partial | no | partial |
| axum-negotiate-layer/axum-negotiate | no | no | no | no | no | no | no | partial | no | no |
| cross-krb5/libgssapi | no | no | no | no | no | partial | partial | yes | no | partial |

## ASN.1 Fixture Probe Matrix

| Fixture | Type | gokrb5 test | rasn-backed decode | rasn-backed round-trip | picky decode | picky round-trip |
|---|---|---|---:|---:|---:|---:|
| `MarshaledKRB5authenticator` | Authenticator | types/Authenticator_test.go | yes | yes | yes | yes |
| `MarshaledKRB5authenticatorOptionalsEmpty` | Authenticator | types/Authenticator_test.go | yes | yes | yes | yes |
| `MarshaledKRB5authenticatorOptionalsNULL` | Authenticator | types/Authenticator_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ticket` | Ticket | messages/Ticket_test.go | yes | yes | yes | yes |
| `MarshaledKRB5keyblock` | EncryptionKey | types/Cryptosystem_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_tkt_part` | EncTicketPart | messages/Ticket_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_tkt_partOptionalsNULL` | EncTicketPart | messages/Ticket_test.go | yes | yes | yes | yes |
| `MarshaledKRB5kdc_req_body` | KdcReqBody | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5kdc_req_bodyOptionalsNULLexceptsecond_ticket` | KdcReqBody | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5kdc_req_bodyOptionalsNULLexceptserver` | KdcReqBody | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5as_req` | AS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket` | AS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5as_reqOptionalsNULLexceptserver` | AS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5tgs_req` | TGS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket` | TGS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5tgs_reqOptionalsNULLexceptserver` | TGS-REQ | messages/KDCReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5as_rep` | AS-REP | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5as_repOptionalsNULL` | AS-REP | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5tgs_rep` | TGS-REP | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5tgs_repOptionalsNULL` | TGS-REP | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_kdc_rep_part` | EncTgsRepPart | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_kdc_rep_partOptionalsNULL` | EncTgsRepPart | messages/KDCRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ap_req` | AP-REQ | messages/APReq_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ap_rep` | AP-REP | messages/APRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ap_rep_enc_part` | EncApRepPart | messages/APRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ap_rep_enc_partOptionalsNULL` | EncApRepPart | messages/APRep_test.go | yes | yes | yes | yes |
| `MarshaledKRB5safe` | KRB-SAFE | messages/KRBSafe_test.go | yes | yes | no | no |
| `MarshaledKRB5safeOptionalsNULL` | KRB-SAFE | messages/KRBSafe_test.go | yes | yes | no | no |
| `MarshaledKRB5priv` | KRB-PRIV | messages/KRBPriv_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_priv_part` | EncKrbPrivPart | messages/KRBPriv_test.go | yes | yes | yes | no |
| `MarshaledKRB5enc_priv_partOptionalsNULL` | EncKrbPrivPart | messages/KRBPriv_test.go | yes | yes | yes | yes |
| `MarshaledKRB5cred` | KRB-CRED | messages/KRBCred_test.go | yes | yes | no | no |
| `MarshaledKRB5enc_cred_part` | EncKrbCredPart | messages/KRBCred_test.go | yes | yes | no | no |
| `MarshaledKRB5enc_cred_partOptionalsNULL` | EncKrbCredPart | messages/KRBCred_test.go | yes | yes | no | no |
| `MarshaledKRB5error` | KRB-ERROR | messages/KRBError_test.go | yes | yes | yes | no |
| `MarshaledKRB5errorOptionalsNULL` | KRB-ERROR | messages/KRBError_test.go | yes | yes | yes | no |
| `MarshaledKRB5authorization_data` | AuthorizationData | types/AuthorizationData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5ad_kdcissued` | AD-KDCIssued | types/AuthorizationData_test.go | yes | yes | no | no |
| `MarshaledKRB5padata_sequence` | PA-DATA sequence | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5padataSequenceEmpty` | PA-DATA sequence | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5typed_data` | TypedData | types/TypedData_test.go | yes | yes | no | no |
| `MarshaledKRB5pa_enc_ts` | PA-ENC-TS-ENC | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5pa_enc_tsNoUsec` | PA-ENC-TS-ENC | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5pa_for_user` | PA-FOR-USER | types/PAData_test.go | yes | yes | no | no |
| `MarshaledKRB5etype_info` | ETYPE-INFO | types/PAData_test.go | yes | yes | no | no |
| `MarshaledKRB5etype_infoOnly1` | ETYPE-INFO | types/PAData_test.go | yes | yes | no | no |
| `MarshaledKRB5etype_infoNoInfo` | ETYPE-INFO | types/PAData_test.go | yes | yes | no | no |
| `MarshaledKRB5etype_info2` | ETYPE-INFO2 | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5etype_info2Only1` | ETYPE-INFO2 | types/PAData_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_data` | EncryptedData | types/Cryptosystem_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_dataMSBSetkvno` | EncryptedData | types/Cryptosystem_test.go | yes | yes | yes | yes |
| `MarshaledKRB5enc_dataKVNONegOne` | EncryptedData | types/Cryptosystem_test.go | yes | yes | yes | yes |
| `MarshaledChangePasswdData` | ChangePasswdData | kadmin/changepasswddata_test.go | yes | yes | yes | yes |

## rasn-kerberos

- License: `MIT OR Apache-2.0`
- Recommendation: Use as a dependency candidate for ASN.1 types, not as a replacement.

| Area | Support | Note |
|---|---:|---|
| Kerberos ASN.1 data types | yes | Provides RFC 4120 types and DER encode/decode through rasn. |
| Message wrappers / exact gokrb5 DER vectors | partial | The translated fixture matrix records decode and exact DER round-trip support across gokrb5 ASN.1 unit-test vectors. |
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
| Message wrappers / exact gokrb5 DER vectors | partial | The translated fixture matrix records decode and exact DER round-trip support, with visible gaps for missing Kerberos shapes. |
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

Proceed with `rskrb5` as the high-level pure-Rust implementation while reusing permissively licensed ASN.1/data-type crates where they pass gokrb5 vectors. Candidate crates remain useful dependencies or references, but none currently supplies a clean gokrb5-equivalent client/service/SPNEGO API. With RFC3962/RFC8009 AES, DES3-CBC-SHA1-KD, and RC4-HMAC coverage, password-derived ktutil-compatible keytab entry generation from explicit principals or SPN-style names, redacted keytab/ccache metadata JSON, X-CACHECONF ccache configuration entry read/write, EncryptedData signed-kvno preservation, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP, KRB-ERROR timing diagnostic decoding, and KRB-CRED decode/decrypt primitives, ChangePasswdData builders and KRB-PRIV payload construction, generic AP-REQ construction, direct AS-service login helpers, complete kpasswd request assembly with generated reply keys, kpasswd AP-REP validation, a high-level Tokio password-change helper with initial kadmin/changepw ticket acquisition and credential update, gokrb5-compatible libdefaults including canonicalize KDC option handling, default_ccache_name, KRB5_CONFIG path-list loading, gokrb5-shaped config JSON, and comment/tab/no-blank-line config variants, per-enctype keytab login/service-ticket integration, keytab file-name helpers with uid/euid token expansion, direct KRB5_KTNAME load/save, and environment-preferred client keytab loading, assumed preauthentication, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP encrypted-padata validation, disable-fast-negotiation AS login control, runtime-neutral and Tokio S4U2Self exchange helpers, and runtime-neutral and Tokio S4U2Proxy request/exchange helpers with impersonated-user reply validation, KRB-ERROR timing surfacing, auto UDP/TCP KDC fallback with Docker AS/TGS, old-KDC password/keytab AS/TGS coverage, negative wrong-keytab and invalid-service KDC-error coverage, configured-KDC TCP failover, and gated kpasswd change/restore plus external kinit/kvno ccache coverage, configured/DNS SRV kpasswd transport and typed kpasswd request/reply/result exchanges, service replay-cache aging/shared-cache state plus file-name, configured-default, and environment-preferred keytab validators, GSSAPI MIC plus sealed/unsealed Wrap vectors, SPNEGO client AP-REQ/header generation with raw KRB5 Negotiate fallback, live Docker HTTP SPNEGO/raw-KRB5 Negotiate acceptance, and live replay-sequence rejection, config/DNS-backed Tokio KDC discovery, cross-realm TGS referral following with cached and renewable referral TGT sessions, configuration validation, structured client diagnostics, gokrb5-style refresh-window checks, primary/realm TGT renewal, cancellable Tokio auto-renewal, affirm-login reuse, Docker-backed destroy semantics, TGT/service-ticket cache removal, S4U2Self acquisition from a current service TGT, S4U2Proxy acquisition from a current service TGT and evidence ticket, unusable-session pruning, duplicate TGT/service-ticket cache selection, invalid TGT cache insertion handling, redacted debug output and zeroize-on-drop for key material, high-level Tokio client file-name and env constructors/write-back, cache JSON/lookup/removal, ccache write-back, KRB5CCNAME load/save, and FILE/WRFILE/DIR cache-name helpers with uid/euid token expansion and environment-preferred default ccache loading/write-back, HTTP/Tower borrowed, owned, file-name, env, configured-default, environment-preferred, shared-replay, and authenticated body-forwarding keytab adapters, an Axum Negotiate example, PAC credentials, UPN/DNS info, group SID derivation, gokrb5-style AD credential summaries, S4U delegation, device info, compressed/uncompressed client/device claims, and gated `TESTAD=1` AD keytab login, no-preauth login, user-domain service-ticket/PAC, and resource-trust service-ticket/PAC parity tests in place, the next implementation work is running the AD gate against a maintained lab and broadening privileged integration coverage.
