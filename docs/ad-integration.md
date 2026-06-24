# Active Directory Integration Gate

The `TESTAD=1` tests mirror the upstream `gokrb5/v8` Active Directory cases for
`github.com/jcmturner/gokrb5/v8` `v8.4.4`. They are live-environment tests, not
Docker MIT fixture tests, and require a maintained two-domain AD lab before they
prove parity.

## What This Gate Proves

The current rskrb5 gate is `tests/client_ad_integration.rs` and covers:

- keytab AS login for `testuser1@USER.GOKRB5`;
- AS login for `testuser3@USER.GOKRB5` where preauthentication is disabled;
- same-domain TGS for `HTTP/user2.user.gokrb5` with AES256-SHA1 session keys;
- service-ticket validation using the service account keytab principal
  `testuser2`, not the ticket SPN;
- cross-domain TGS through the `USER.GOKRB5` to `RES.GOKRB5` trust with
  canonicalization and RC4-HMAC enabled;
- PAC extraction and AD credential summary checks for same-domain and
  resource-domain tickets.

The broader PAC unit tests cover trusted-domain validation info, extra SIDs,
resource groups, checksum rejection, and AD claims vectors. The live gate is the
remaining proof that those parsers match tickets issued by AD.

## Lab Contract

The lab must provide two reachable AD domains with the gokrb5-compatible realm
and DNS names:

| Realm | Domain | Default KDC | Default admin server |
|---|---|---|---|
| `USER.GOKRB5` | `user.gokrb5` | `192.168.88.100:88` | `192.168.88.100:464` |
| `RES.GOKRB5` | `res.gokrb5` | `192.168.88.101:88` | `192.168.88.101:464` |

DNS KDC lookup is disabled in the test config. Override endpoints when the lab
does not use the default gokrb5 fixture addresses:

```sh
export TEST_AD_USER_KDC_ADDR=192.168.88.100:88
export TEST_AD_RESOURCE_KDC_ADDR=192.168.88.101:88
export TEST_AD_USER_ADMIN_ADDR=192.168.88.100:464
export TEST_AD_RESOURCE_ADMIN_ADDR=192.168.88.101:464
```

Fallback endpoint names remain supported for compatibility:
`TEST_AD_KDC_ADDR`, `TEST_AD_RES_KDC_ADDR`, `TEST_AD_ADMIN_ADDR`, and
`TEST_AD_RES_ADMIN_ADDR`.

The domains must have a bidirectional trust. The test config sets
`forwardable = yes`, `noaddresses = false`, AES256-SHA1 enctypes by default,
and RC4-HMAC plus canonicalization for the trust tests.

The required principals and SPNs are:

| Principal | Realm | Required behavior |
|---|---|---|
| `testuser1` | `USER.GOKRB5` | normal keytab login client |
| `testuser2` | `USER.GOKRB5` | service account for `HTTP/user2.user.gokrb5` |
| `testuser3` | `USER.GOKRB5` | preauthentication disabled |
| `sysHTTP` | `RES.GOKRB5` | service account for `HTTP/host.res.gokrb5` |

The checked-in tests default to embedded upstream-compatible keytab bytes for
those accounts. A maintained lab can either preserve those account keys and
kvnos or supply lab-specific keytabs through environment variables.

## Keytab Overrides

Each AD identity can be supplied as a file path, hex-encoded keytab bytes, or
standard base64-encoded keytab bytes. Path overrides take precedence over hex,
and hex takes precedence over base64.

| Identity | Path variable | Hex variable | Base64 variable |
|---|---|---|---|
| `testuser1@USER.GOKRB5` | `TEST_AD_TESTUSER1_KEYTAB_PATH` | `TEST_AD_TESTUSER1_KEYTAB_HEX` | `TEST_AD_TESTUSER1_KEYTAB_BASE64` |
| `testuser2@USER.GOKRB5` | `TEST_AD_TESTUSER2_KEYTAB_PATH` | `TEST_AD_TESTUSER2_KEYTAB_HEX` | `TEST_AD_TESTUSER2_KEYTAB_BASE64` |
| `testuser3@USER.GOKRB5` | `TEST_AD_TESTUSER3_KEYTAB_PATH` | `TEST_AD_TESTUSER3_KEYTAB_HEX` | `TEST_AD_TESTUSER3_KEYTAB_BASE64` |
| `sysHTTP@RES.GOKRB5` | `TEST_AD_SYSHTTP_KEYTAB_PATH` | `TEST_AD_SYSHTTP_KEYTAB_HEX` | `TEST_AD_SYSHTTP_KEYTAB_BASE64` |

For GitHub Actions, the manual integration job reads the corresponding
`*_BASE64` secret names when `test_ad=true`. For local or self-hosted runs,
file paths are usually simpler:

```sh
export TEST_AD_TESTUSER1_KEYTAB_PATH=/secure/ad/testuser1.keytab
export TEST_AD_TESTUSER2_KEYTAB_PATH=/secure/ad/testuser2.keytab
export TEST_AD_TESTUSER3_KEYTAB_PATH=/secure/ad/testuser3.keytab
export TEST_AD_SYSHTTP_KEYTAB_PATH=/secure/ad/sysHTTP.keytab
```

Hex and base64 values may contain whitespace. The decoded bytes must be a
complete MIT keytab containing keys for the named account.

## Running The Gate

For a discovery/debug run that may soft-skip when endpoints are unavailable:

```sh
TESTAD=1 cargo test --all-features --test client_ad_integration -- --nocapture
```

For release or parity evidence, require the lab to be reachable:

```sh
TESTAD=1 TESTAD_REQUIRED=1 \
  cargo test --all-features --test client_ad_integration -- --nocapture
```

`TESTAD_REQUIRED=1` fails the test when `TESTAD=1` is missing or either AD KDC
cannot be reached. Without it, the tests keep the upstream-style behavior of
returning `Ok(())` after printing a skip diagnostic.

When running through the Docker MIT fixture helper, AD remains separate from the
Docker environment. The helper preserves `TEST_AD_*` endpoint and keytab values
in `target/gated-integration.env` for split `start` and `test` workflows, but
it does not create AD domains:

```sh
TESTAD=1 TESTAD_REQUIRED=1 scripts/run-gated-integration.sh test \
  --test client_ad_integration -- --nocapture
```

Use a runner that can route to both AD KDCs and keep clock skew within Kerberos
tolerance. A GitHub-hosted runner will only pass this gate if the lab is exposed
or reachable through a configured network path.

## Upstream Mapping

The rskrb5 tests correspond to the upstream `gokrb5/v8` cases:

| rskrb5 test | Upstream behavior |
|---|---|
| `active_directory_keytab_login` | `TestClient_SuccessfulLogin_AD` |
| `active_directory_keytab_login_without_preauth` | `TestClient_SuccessfulLogin_AD_Without_PreAuth` |
| `active_directory_service_ticket_validates_user_domain_pac` | `TestClient_GetServiceTicket_AD` |
| `active_directory_trust_resource_domain_service_ticket_validates_pac` | `TestClient_GetServiceTicket_AD_TRUST_USER_DOMAIN` |
| `active_directory_trust_user_domain_service_ticket_validates_pac` | `TestClient_GetServiceTicket_AD_USER_DOMAIN` |

Keep the gate marked `blocked-on-lab` until the strict command above completes
against a maintained lab and the run evidence is recorded in
`docs/gokrb5-parity.md` and `docs/gokrb5-parity.toml`.
