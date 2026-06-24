# Active Directory Lab Provisioning

This runbook defines the live AD lab contract for the strict gokrb5 parity
gate. It complements [`ad-integration.md`](ad-integration.md), which documents
the Rust test behavior and environment variables.

## Domains

Provision two Active Directory domains:

| Realm | DNS domain | NetBIOS | Default KDC | Default admin |
|---|---|---|---|---|
| `USER.GOKRB5` | `user.gokrb5` | `USER` | `192.168.88.100:88` | `192.168.88.100:464` |
| `RES.GOKRB5` | `res.gokrb5` | `RES` | `192.168.88.101:88` | `192.168.88.101:464` |

The tests disable DNS KDC discovery. If the lab uses different addresses, set
the endpoint variables or GitHub secrets documented in
[`ad-integration.md`](ad-integration.md) and
[`github-ad-gate-setup.md`](github-ad-gate-setup.md).

Create a bidirectional trust between `USER.GOKRB5` and `RES.GOKRB5`. The
resource-domain tests rely on AD referrals with Kerberos canonicalization
enabled; there is no `[capaths]` fallback in the test config.

## Accounts And SPNs

Create enabled, non-expired accounts with stable passwords:

| Account | Domain | Required use |
|---|---|---|
| `testuser1` | `USER` | normal keytab AS login client |
| `testuser2` | `USER` | service account for `HTTP/user2.user.gokrb5` |
| `testuser3` | `USER` | AS login client with Kerberos preauth disabled |
| `sysHTTP` | `RES` | service account for `HTTP/host.res.gokrb5` |

Register these SPNs uniquely:

```powershell
setspn -S HTTP/user2.user.gokrb5 USER\testuser2
setspn -S HTTP/host.res.gokrb5 RES\sysHTTP
```

The service keytabs must contain account-principal entries used by the tests:

- `testuser2@USER.GOKRB5`
- `sysHTTP@RES.GOKRB5`

They must not contain only SPN-principal entries. The test intentionally
validates service tickets by selecting those account principals from the
service keytabs.

## Preauth And Enctypes

Disable Kerberos preauthentication only for `testuser3`. Leave preauth required
for `testuser1`, `testuser2`, and `sysHTTP`.

Required crypto behavior:

- AES256-SHA1, etype `18`, for normal AS and same-domain TGS paths.
- RC4-HMAC, etype `23`, for the resource-domain trust and canonicalization
  scenario.

Allow AES256 and RC4 on all four keytab accounts and on the trust path. If the
lab baseline disables RC4, the resource-domain trust test will fail because it
asserts an RC4-HMAC session key for `HTTP/host.res.gokrb5`.

## Keytab Export

Export complete MIT keytabs for the four account principals:

| Principal | Local env path | GitHub secret |
|---|---|---|
| `testuser1@USER.GOKRB5` | `TEST_AD_TESTUSER1_KEYTAB_PATH` | `TEST_AD_TESTUSER1_KEYTAB_BASE64` |
| `testuser2@USER.GOKRB5` | `TEST_AD_TESTUSER2_KEYTAB_PATH` | `TEST_AD_TESTUSER2_KEYTAB_BASE64` |
| `testuser3@USER.GOKRB5` | `TEST_AD_TESTUSER3_KEYTAB_PATH` | `TEST_AD_TESTUSER3_KEYTAB_BASE64` |
| `sysHTTP@RES.GOKRB5` | `TEST_AD_SYSHTTP_KEYTAB_PATH` | `TEST_AD_SYSHTTP_KEYTAB_BASE64` |

The keytab kvno and keys must match the current AD account state. Re-export the
keytab after any password reset or enctype change.

For GitHub Actions, store base64 of the raw keytab bytes. Whitespace is
accepted by the preflight script, but the secret examples in
[`github-ad-gate-setup.md`](github-ad-gate-setup.md) strip newlines to keep the
stored value simple.

## Network And Clock

The runner or local test host must be able to reach both domain controllers.
The preflight checks TCP `88`; the Rust tests use `KdcProtocol::Auto`, so allow
both UDP and TCP `88` from the runner to each KDC. Admin endpoint values are
required for the config and CI secrets. Their TCP `464` reachability is checked
only when `TEST_AD_CHECK_ADMIN_REACHABILITY=1`.

The default GitHub Actions gate runs on GitHub-hosted `ubuntu-latest`, so the
KDC endpoints must be reachable from GitHub-hosted runners. Private lab
addresses need a tunnel or a workflow change back to a self-hosted runner near
the lab.

Keep the runner, USER domain controller, and RES domain controller clocks within
normal Kerberos skew tolerance.

## Validation Sequence

Validate the local environment before running Rust tests:

```sh
export TESTAD=1
export TESTAD_REQUIRED=1
export TEST_AD_REQUIRE_EXPLICIT_ENDPOINTS=1
export TEST_AD_REQUIRE_KEYTAB_OVERRIDES=1

scripts/check-ad-integration-env.py
cargo test --all-features --test client_ad_integration -- --nocapture
```

Expected strict evidence:

- `testuser1@USER.GOKRB5` obtains an AES256 TGT;
- `testuser3@USER.GOKRB5` obtains an AES256 TGT without preauth;
- `HTTP/user2.user.gokrb5` returns an AES256 same-domain service ticket with
  PAC domain `USER`;
- `HTTP/host.res.gokrb5` returns an RC4 resource-domain trust ticket;
- validated PAC credentials keep effective user `testuser1`.

For GitHub Actions, run the readiness and dispatch sequence in
[`github-ad-gate-setup.md`](github-ad-gate-setup.md).
