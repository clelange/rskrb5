# Gated Integration Validation

The gated integration tests reuse the gokrb5 Docker fixtures. Use the checked-in
runner so local validation and GitHub Actions use the same container names,
ports, and environment variables.

## Local Run

Run the full Docker-backed suite:

```sh
scripts/run-gated-integration.sh run
```

Run the password-change gate as well:

```sh
TEST_KPASSWD=1 scripts/run-gated-integration.sh run
```

Run one focused test while keeping the containers available for inspection:

```sh
RSKRB5_KEEP_CONTAINERS=1 scripts/run-gated-integration.sh run \
  --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture
scripts/run-gated-integration.sh stop
```

The `start` command writes `target/gated-integration.env`. To run custom cargo
commands against already-started fixtures:

```sh
scripts/run-gated-integration.sh start
scripts/run-gated-integration.sh env
scripts/run-gated-integration.sh test --test client_integration
scripts/run-gated-integration.sh stop
```

## Resolver Behavior

The DNS-SRV test uses the OS resolver through the Rust DNS resolver stack, so
the DNS fixture must be the active resolver while `TEST_DNS_KDC=1` is set. The
resolver configuration defaults to:

```sh
RSKRB5_CONFIGURE_RESOLVER=1 # Linux
RSKRB5_CONFIGURE_RESOLVER=0 # other local platforms
```

With `RSKRB5_CONFIGURE_RESOLVER=1`, the runner backs up `/etc/resolv.conf`,
writes the DNS fixture nameserver, and restores the backup during `stop`. If
that is too invasive for local debugging, disable DNS or resolver mutation:

```sh
TEST_DNS_KDC=0 scripts/run-gated-integration.sh run
RSKRB5_CONFIGURE_RESOLVER=0 scripts/run-gated-integration.sh start
```

When resolver configuration is disabled, `TEST_DNS_KDC` defaults to `0` so the
Rust DNS-SRV gate is skipped. The generated `target/gated-integration.env` still
records `DNS_IP`; on Docker backends that expose container IPs directly, this is
the DNS container IP rather than the loopback publish address.
`TEST_HTTP_URL` also defaults to `http://127.0.0.1` in this mode so the live
HTTP Negotiate tests do not depend on DNS.

When diagnosing DNS directly, query the fixture before running Rust tests:

```sh
source target/gated-integration.env
dig @"$DNS_IP" -p 53 _kerberos._udp.TEST.GOKRB5 SRV
dig @"$DNS_IP" -p 53 cname.test.gokrb5 A
```

## macOS And Privileged Gates

On Darwin the runner defaults `RSKRB5_DIRECT_CONTAINER_IP=1`. This points the
Rust tests at Docker container IPs instead of host-forwarded KDC ports, which
avoids address-bound ticket mismatches seen with external `kinit`/`kvno`
coverage on local Docker backends. Override it when forwarded ports are known to
work:

```sh
RSKRB5_DIRECT_CONTAINER_IP=0 scripts/run-gated-integration.sh run
```

To run the DNS-SRV gate locally on Darwin, opt in to resolver mutation from an
interactive shell that can run `sudo`:

```sh
RSKRB5_CONFIGURE_RESOLVER=1 TEST_DNS_KDC=1 scripts/run-gated-integration.sh run
```

`TESTPRIVILEGED=1` is enabled by default and requires system Kerberos tools
(`kinit`, `kvno`) on `PATH`. On Homebrew installations:

```sh
PATH="/opt/homebrew/opt/krb5/bin:$PATH" scripts/run-gated-integration.sh run
```

## Active Directory Gate

`TESTAD=1` is not bootstrapped by this script. It needs the separate AD lab
documented in [`ad-integration.md`](ad-integration.md) or equivalent endpoints
supplied through `TEST_AD_USER_KDC_ADDR`, `TEST_AD_RESOURCE_KDC_ADDR`,
`TEST_AD_USER_ADMIN_ADDR`, and `TEST_AD_RESOURCE_ADMIN_ADDR`.

Use `TESTAD_REQUIRED=1` for release or parity evidence so unreachable AD
endpoints fail instead of soft-skipping:

```sh
TESTAD=1 TESTAD_REQUIRED=1 cargo test --all-features --test client_ad_integration -- --nocapture
```
