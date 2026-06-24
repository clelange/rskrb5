# Samba AD Feasibility Spike

This is the backup path while no maintained Windows AD lab or reachable private
runner is available. A Samba AD lab can help exercise AD-like Kerberos, PAC, SPN,
and trust behavior, but it is not a substitute for strict Windows AD evidence
until the same `TESTAD=1 TESTAD_REQUIRED=1` gate passes against a reachable lab.

## Goal

Determine whether a Samba-based two-domain lab can satisfy the existing
`tests/client_ad_integration.rs` contract:

- `USER.GOKRB5` and `RES.GOKRB5` realms;
- bidirectional trust and referrals between the realms;
- `testuser1`, `testuser2`, `testuser3`, and `sysHTTP` account principals;
- `HTTP/user2.user.gokrb5` and `HTTP/host.res.gokrb5` SPNs;
- preauthentication disabled only for `testuser3`;
- AES256 for normal AS/TGS paths and RC4-HMAC for the resource-domain trust
  scenario;
- keytab login, no-preauth login, same-domain PAC validation, and
  resource-domain PAC validation.

## What It Can Prove

A successful Samba spike can prove that the rskrb5 AD gate wiring, keytab
override plumbing, cross-realm referrals, service validation, and PAC parsing
work against a maintained AD-like KDC.

It cannot by itself prove full Windows AD parity. Keep the parity status at
`blocked-on-lab` until the strict gate passes against the intended AD target and
the evidence is recorded in `docs/gokrb5-parity.md` and
`docs/gokrb5-parity.toml`.

## Feasibility Preflight

Run the local host preflight:

```sh
scripts/check-samba-ad-feasibility.py
```

For a local TCP port probe:

```sh
scripts/check-samba-ad-feasibility.py --check-ports
```

The preflight checks Docker, Docker Compose, host OS, and optionally common AD
TCP ports. On macOS, Docker Desktop is useful for prototyping but does not make
the lab reachable from GitHub-hosted runners. GitHub-hosted proof still needs
public or tunneled endpoints.

## Prototype Shape

Use two Samba domain controllers, preferably on a Linux host or VM:

| Realm | DNS domain | NetBIOS | KDC | Admin |
|---|---|---|---|---|
| `USER.GOKRB5` | `user.gokrb5` | `USER` | `host:88` | `host:464` |
| `RES.GOKRB5` | `res.gokrb5` | `RES` | `host:88` | `host:464` |

The prototype must expose KDC and kpasswd/admin endpoints that can be referenced
through the same GitHub secrets used by the strict gate:

- `TEST_AD_USER_KDC_ADDR`
- `TEST_AD_RESOURCE_KDC_ADDR`
- `TEST_AD_USER_ADMIN_ADDR`
- `TEST_AD_RESOURCE_ADMIN_ADDR`

If the lab is only local to a developer laptop, run the strict gate locally and
record it as local evidence only. Do not mark the GitHub AD gate proven.

## Account Contract

Provision accounts with the generated keytab passwords or regenerate keytabs
from the final account passwords:

| Account | Realm | Required behavior |
|---|---|---|
| `testuser1` | `USER.GOKRB5` | normal keytab AS login client |
| `testuser2` | `USER.GOKRB5` | service account for `HTTP/user2.user.gokrb5` |
| `testuser3` | `USER.GOKRB5` | preauthentication disabled |
| `sysHTTP` | `RES.GOKRB5` | service account for `HTTP/host.res.gokrb5` |

Register SPNs uniquely:

```text
HTTP/user2.user.gokrb5 -> USER\testuser2
HTTP/host.res.gokrb5 -> RES\sysHTTP
```

Export account-principal keytabs, not SPN-only keytabs:

- `testuser1@USER.GOKRB5`
- `testuser2@USER.GOKRB5`
- `testuser3@USER.GOKRB5`
- `sysHTTP@RES.GOKRB5`

## Validation Sequence

Start with the non-live GitHub keytab secret dry-run:

```sh
scripts/check-github-ad-gate.py --dry-run --dispatch --ref main
```

Then run the strict local preflight against the Samba endpoints:

```sh
export TESTAD=1
export TESTAD_REQUIRED=1
export TEST_AD_REQUIRE_EXPLICIT_ENDPOINTS=1
export TEST_AD_REQUIRE_KEYTAB_OVERRIDES=1

scripts/check-ad-integration-env.py
cargo test --all-features --test client_ad_integration -- --nocapture
```

Only after the strict local run passes should the endpoints be considered for
GitHub-hosted `test_ad=true` dispatch.

## Known Risks

- Samba PAC contents, trust behavior, and enctype policy can differ from Windows
  AD.
- RC4-HMAC may require explicit policy changes.
- Docker Desktop networking can hide UDP/TCP, DNS, and low-port behavior that
  differs from Linux.
- GitHub-hosted runners cannot reach local laptop containers without a tunnel or
  public endpoint.

Treat any Samba result as feasibility evidence until the same strict gate passes
in the target release environment.
