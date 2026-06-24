# GitHub Active Directory Gate Setup

This runbook prepares the strict `TESTAD=1 TESTAD_REQUIRED=1` GitHub Actions
gate. The gate is live infrastructure evidence, not a Docker fixture. Keep it
blocked until the repository has the required secrets and reachable AD
endpoints.

## Runner Mode

The default `active-directory-integration` job runs on GitHub-hosted
`ubuntu-latest`. No self-hosted runner is required for the current workflow.

GitHub-hosted runners can prove the strict AD gate only when the AD endpoints
are reachable from GitHub's network or through a tunnel started by the workflow.
If the AD lab is private, either expose a controlled route or switch the job
back to a self-hosted Linux x64 runner near the lab.

The legacy self-hosted runner mode expects these labels:

- `self-hosted`
- `linux`
- `x64`
- `rskrb5-ad`

Use this registration sequence only if the workflow is changed back to the
self-hosted runner labels:

```sh
REPO=clelange/rskrb5
TOKEN=$(gh api --method POST "repos/$REPO/actions/runners/registration-token" --jq .token)

# Run inside the extracted GitHub Actions runner directory.
./config.sh --url "https://github.com/$REPO" --token "$TOKEN" --labels rskrb5-ad
./svc.sh install
./svc.sh start
```

Do not store the registration token. It is short-lived and should only be used
on the runner host.

## Network Requirements

The runner must satisfy these operational requirements:

- Linux x64 environment with outbound GitHub access for Actions checkout and
  toolchain setup.
- Network route from the runner to both AD KDC endpoints on TCP and UDP `88`.
- Network route to both kpasswd/admin endpoints on TCP `464` when
  `TEST_AD_CHECK_ADMIN_REACHABILITY=1` is used.
- Clock synchronized with both domain controllers inside normal Kerberos skew
  tolerance.
- Access to the AD lab described in [`ad-lab-provisioning.md`](ad-lab-provisioning.md).

The workflow installs the Rust toolchain itself. No keytabs live on disk on the
runner before the job starts; the job reads keytab bytes from Actions secrets.

## Required Secrets

Set these repository Actions secrets. Repository or org repo-selected secrets
work. Do not rely on Environment secrets unless the workflow is changed to set
an `environment:` for the AD job.

Endpoint secrets are plain `host:port` strings:

| Secret | Example |
|---|---|
| `TEST_AD_USER_KDC_ADDR` | `192.168.88.100:88` |
| `TEST_AD_RESOURCE_KDC_ADDR` | `192.168.88.101:88` |
| `TEST_AD_USER_ADMIN_ADDR` | `192.168.88.100:464` |
| `TEST_AD_RESOURCE_ADMIN_ADDR` | `192.168.88.101:464` |

Keytab secrets are standard base64 of the complete MIT keytab bytes:

| Secret | Keytab content |
|---|---|
| `TEST_AD_TESTUSER1_KEYTAB_BASE64` | `testuser1@USER.GOKRB5` |
| `TEST_AD_TESTUSER2_KEYTAB_BASE64` | `testuser2@USER.GOKRB5` |
| `TEST_AD_TESTUSER3_KEYTAB_BASE64` | `testuser3@USER.GOKRB5` |
| `TEST_AD_SYSHTTP_KEYTAB_BASE64` | `sysHTTP@RES.GOKRB5` |

Example secret setup:

```sh
REPO=clelange/rskrb5

printf '%s' '192.168.88.100:88'  | gh secret set TEST_AD_USER_KDC_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.101:88'  | gh secret set TEST_AD_RESOURCE_KDC_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.100:464' | gh secret set TEST_AD_USER_ADMIN_ADDR --repo "$REPO" --app actions
printf '%s' '192.168.88.101:464' | gh secret set TEST_AD_RESOURCE_ADMIN_ADDR --repo "$REPO" --app actions

base64 < /secure/ad/testuser1.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER1_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/testuser2.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER2_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/testuser3.keytab | tr -d '\n' | gh secret set TEST_AD_TESTUSER3_KEYTAB_BASE64 --repo "$REPO" --app actions
base64 < /secure/ad/sysHTTP.keytab   | tr -d '\n' | gh secret set TEST_AD_SYSHTTP_KEYTAB_BASE64 --repo "$REPO" --app actions
```

## Readiness And Dispatch

Check GitHub-side readiness before dispatching the strict gate:

```sh
scripts/check-github-ad-gate.py
```

The readiness script must report all required secrets present. It does not
prove that GitHub-hosted runners can reach the AD endpoints; the workflow
preflight checks that from inside GitHub Actions.

To validate only the keytab secret shape without requiring live AD endpoints,
run the non-live dry-run check:

```sh
scripts/check-github-ad-gate.py --dry-run
```

Dispatching the dry-run job is allowed while the endpoint secrets are absent:

```sh
scripts/check-github-ad-gate.py --dry-run --dispatch --ref main
```

This runs `test_ad_dry_run=true` on GitHub-hosted `ubuntu-latest`, checks that
the four keytab secrets decode as complete keytabs, and skips endpoint
reachability. It does not prove AD parity.

To also check the legacy self-hosted runner labels, pass
`--require-self-hosted-runner`.

Dispatch the strict AD job only after readiness is green:

```sh
scripts/check-github-ad-gate.py --dispatch --ref main
```

Direct equivalent:

```sh
gh workflow run ci.yml --repo clelange/rskrb5 --ref main \
  -f integration=false \
  -f test_ad=true \
  -f test_ad_dry_run=false \
  -f test_kpasswd=false
```

## Failure Triage

Common external blockers:

- required secret missing or set to an empty value;
- GitHub-hosted runner cannot reach one or both KDCs on TCP `88`;
- endpoint secret is not `host:port`;
- keytab secret is not valid base64 or is not a complete MIT keytab;
- keytab principal, kvno, enctype, or password is stale relative to AD;
- required SPN or bidirectional trust is missing;
- RC4-HMAC is disabled for the resource-domain trust scenario;
- runner and domain-controller clocks are outside Kerberos skew tolerance.

If the readiness script stays red, keep `docs/gokrb5-parity.toml` and
`docs/gokrb5-parity.md` at `blocked-on-lab`.
