#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${RSKRB5_INTEGRATION_ENV_FILE:-"$ROOT_DIR/target/gated-integration.env"}"
RESOLV_CONF_BACKUP="${RSKRB5_RESOLV_CONF_BACKUP:-"$ROOT_DIR/target/resolv.conf.rskrb5.backup"}"

CONTAINERS=(
  dns
  krb5kdc
  krb5kdc-old
  krb5kdc-latest
  krb5kdc-resdom
  krb5kdc-shorttickets
  gokrb5-http
)

usage() {
  cat <<'EOF'
Usage: scripts/run-gated-integration.sh <command> [cargo-test-args...]

Commands:
  start       Start gokrb5 Docker integration fixtures and write target/gated-integration.env.
  test        Source target/gated-integration.env and run cargo test --all-features.
  run         Start fixtures, run tests, then stop fixtures unless RSKRB5_KEEP_CONTAINERS=1.
  stop        Stop known fixture containers and restore /etc/resolv.conf when a backup exists.
  env         Print the generated integration environment.

Useful environment:
  TEST_KPASSWD=1                 Enable live password-change coverage.
  TESTAD=1                       Enable Active Directory tests, if the lab is reachable.
  TEST_DNS_KDC=1                 Enable DNS-SRV KDC discovery tests.
                                 Defaults to resolver configuration mode.
  TESTPRIVILEGED=1               Enable external kinit/kvno coverage. Defaults to 1.
  RSKRB5_CONFIGURE_RESOLVER=1    Point /etc/resolv.conf at the DNS fixture.
                                 Defaults to 1 on Linux and 0 elsewhere.
  RSKRB5_DIRECT_CONTAINER_IP=1   Use Docker container IPs instead of forwarded ports.
                                 Defaults to 1 on Darwin and 0 elsewhere.
  RSKRB5_KEEP_CONTAINERS=1       Keep containers after the run command exits.
  DOCKER_PLATFORM=linux/amd64    Optional Docker --platform override.

Examples:
  scripts/run-gated-integration.sh run
  TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration
  scripts/run-gated-integration.sh start
  scripts/run-gated-integration.sh test --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture
  scripts/run-gated-integration.sh stop
EOF
}

docker_sudo=()
if [[ "$(id -u)" != "0" ]] && ! docker ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1; then
    docker_sudo=(sudo)
  fi
fi

docker_cmd() {
  "${docker_sudo[@]}" docker "$@"
}

sudo_cmd() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

docker_platform_args() {
  if [[ -n "${DOCKER_PLATFORM:-}" ]]; then
    printf '%s\n' --platform "$DOCKER_PLATFORM"
  fi
}

stop_containers() {
  docker_cmd rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
}

restore_resolver() {
  if [[ -f "$RESOLV_CONF_BACKUP" ]]; then
    sudo_cmd cp "$RESOLV_CONF_BACKUP" /etc/resolv.conf
    rm -f "$RESOLV_CONF_BACKUP"
  fi
}

stop_all() {
  stop_containers
  restore_resolver
}

container_ip() {
  docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

container_gateway() {
  docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$1"
}

relax_dns_acl() {
  docker_cmd exec dns sh -lc \
    "ready=0; for _ in 1 2 3 4 5 6 7 8 9 10; do rndc status >/dev/null 2>&1 && ready=1 && break; sleep 1; done; test \"\$ready\" = 1 && sed -i 's/allow-query[[:space:]]*{[^}]*};/allow-query { any; };/' /etc/named.conf && rndc reconfig"
}

strip_port() {
  local value="$1"
  if [[ "$value" == *:* && "${value##*:}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${value%:*}"
  else
    printf '%s\n' "$value"
  fi
}

configure_resolver() {
  local dns_ip="$1"
  local enabled="$2"

  if [[ "$enabled" != "1" ]]; then
    return
  fi

  mkdir -p "$(dirname "$RESOLV_CONF_BACKUP")"
  if [[ ! -f "$RESOLV_CONF_BACKUP" ]]; then
    sudo_cmd cp /etc/resolv.conf "$RESOLV_CONF_BACKUP"
  fi
  printf 'nameserver %s\n' "$dns_ip" | sudo_cmd tee /etc/resolv.conf >/dev/null
}

default_configure_resolver_enabled() {
  local enabled="${RSKRB5_CONFIGURE_RESOLVER:-}"
  if [[ -z "$enabled" ]]; then
    if [[ "$(uname -s)" == "Linux" ]]; then
      enabled=1
    else
      enabled=0
    fi
  fi
  printf '%s\n' "$enabled"
}

dig_short() {
  local server="$1"
  local name="$2"
  local record_type="$3"
  local host="${server%:*}"
  local port="${server##*:}"

  if [[ "$server" != *:* || ! "$port" =~ ^[0-9]+$ ]]; then
    host="$server"
    port=53
  fi

  dig @"$host" -p "$port" +time=1 +tries=1 +short "$name" "$record_type"
}

wait_for_dns_fixture() {
  local dns_server="$1"
  local http_addr="$2"

  if ! command -v dig >/dev/null 2>&1; then
    echo "dig not found; skipping DNS fixture readiness check." >&2
    return
  fi

  local srv_answer=""
  local http_answer=""
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    srv_answer="$(dig_short "$dns_server" _kerberos._udp.test.gokrb5 SRV 2>&1 || true)"
    http_answer="$(dig_short "$dns_server" cname.test.gokrb5 A 2>&1 || true)"
    if [[ "$srv_answer" == *"kdc.test.gokrb5."* && "$http_answer" == *"$http_addr"* ]]; then
      return
    fi
    sleep 1
  done

  {
    echo "DNS fixture did not become ready at $dns_server."
    echo "Last _kerberos._udp.test.gokrb5 SRV answer:"
    echo "$srv_answer"
    echo "Last cname.test.gokrb5 A answer:"
    echo "$http_answer"
  } >&2
  return 1
}

verify_configured_resolver() {
  local http_addr="$1"

  if ! command -v dig >/dev/null 2>&1; then
    echo "dig not found; skipping configured resolver verification." >&2
    return
  fi

  local srv_answer=""
  local http_answer=""
  for _ in 1 2 3 4 5; do
    srv_answer="$(dig +time=1 +tries=1 +short _kerberos._udp.test.gokrb5 SRV 2>&1 || true)"
    http_answer="$(dig +time=1 +tries=1 +short cname.test.gokrb5 A 2>&1 || true)"
    if [[ "$srv_answer" == *"kdc.test.gokrb5."* && "$http_answer" == *"$http_addr"* ]]; then
      return
    fi
    sleep 1
  done

  {
    echo "Configured resolver cannot query the DNS fixture."
    echo "Last _kerberos._udp.test.gokrb5 SRV answer:"
    echo "$srv_answer"
    echo "Last cname.test.gokrb5 A answer:"
    echo "$http_answer"
  } >&2
  return 1
}

write_env() {
  local primary_addr="$1"
  local old_addr="$2"
  local latest_addr="$3"
  local resdom_addr="$4"
  local short_addr="$5"
  local kpasswd_addr="$6"
  local kpasswd_sender_addr="$7"
  local dns_ip="$8"
  local dns_override_ns="$9"
  local http_url="${10}"
  local http_addr="${11}"
  local test_dns_kdc="${12}"

  mkdir -p "$(dirname "$ENV_FILE")"
  cat >"$ENV_FILE" <<EOF
export INTEGRATION=1
export TESTPRIVILEGED=${TESTPRIVILEGED:-1}
export TESTAD=${TESTAD:-0}
export TEST_KPASSWD=${TEST_KPASSWD:-0}
export TEST_DNS_KDC=$test_dns_kdc
export TEST_KDC_ADDR=$primary_addr
export TEST_OLD_KDC_ADDR=$old_addr
export TEST_LATEST_KDC_ADDR=$latest_addr
export TEST_RESDOM_KDC_ADDR=$resdom_addr
export TEST_SHORT_KDC_ADDR=$short_addr
export TEST_KPASSWD_ADDR=$kpasswd_addr
export TEST_KPASSWD_SADDR=$kpasswd_sender_addr
export TEST_HTTP_URL=$http_url
export TEST_HTTP_ADDR=$http_addr
export DNS_IP=$dns_ip
export DNSUTILS_OVERRIDE_NS=$dns_override_ns
EOF
}

start_fixtures() {
  local platform_args=()
  while IFS= read -r arg; do
    platform_args+=("$arg")
  done < <(docker_platform_args)

  stop_containers

  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 88:88 -p 88:88/udp -p 464:464 -p 464:464/udp \
    --name krb5kdc jcmturner/gokrb5:kdc-centos-default >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 78:88 -p 78:88/udp \
    --name krb5kdc-old jcmturner/gokrb5:kdc-older >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 98:88 -p 98:88/udp \
    --name krb5kdc-latest jcmturner/gokrb5:kdc-latest >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.resdom.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 188:88 -p 188:88/udp \
    --name krb5kdc-resdom jcmturner/gokrb5:kdc-resdom >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 58:88 -p 58:88/udp \
    --name krb5kdc-shorttickets jcmturner/gokrb5:kdc-shorttickets >/dev/null
  docker_cmd run -d "${platform_args[@]}" \
    --add-host host.test.gokrb5:127.0.0.88 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 80:80 -p 443:443 \
    --name gokrb5-http jcmturner/gokrb5:http >/dev/null

  local direct="${RSKRB5_DIRECT_CONTAINER_IP:-}"
  if [[ -z "$direct" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      direct=1
    else
      direct=0
    fi
  fi

  local configure_resolver_enabled
  configure_resolver_enabled="$(default_configure_resolver_enabled)"
  local test_dns_kdc="${TEST_DNS_KDC:-$configure_resolver_enabled}"

  local primary_addr old_addr latest_addr resdom_addr short_addr kpasswd_addr kpasswd_sender_addr
  local dns_kdc_addr
  if [[ "$direct" == "1" ]]; then
    local primary_ip old_ip latest_ip resdom_ip short_ip
    primary_ip="$(container_ip krb5kdc)"
    old_ip="$(container_ip krb5kdc-old)"
    latest_ip="$(container_ip krb5kdc-latest)"
    resdom_ip="$(container_ip krb5kdc-resdom)"
    short_ip="$(container_ip krb5kdc-shorttickets)"
    primary_addr="$primary_ip:88"
    old_addr="$old_ip:88"
    latest_addr="$latest_ip:88"
    resdom_addr="$resdom_ip:88"
    short_addr="$short_ip:88"
    kpasswd_addr="$primary_ip:464"
    kpasswd_sender_addr="${TEST_KPASSWD_SADDR:-"$(container_gateway krb5kdc)"}"
    dns_kdc_addr="$primary_ip"
  else
    primary_addr="${TEST_KDC_ADDR:-127.0.0.1}"
    old_addr="${TEST_OLD_KDC_ADDR:-127.0.0.1}"
    latest_addr="${TEST_LATEST_KDC_ADDR:-127.0.0.1}"
    resdom_addr="${TEST_RESDOM_KDC_ADDR:-127.0.0.1}"
    short_addr="${TEST_SHORT_KDC_ADDR:-127.0.0.1}"
    kpasswd_addr="${TEST_KPASSWD_ADDR:-127.0.0.1}"
    kpasswd_sender_addr="${TEST_KPASSWD_SADDR:-127.0.0.1}"
    dns_kdc_addr="$(strip_port "$primary_addr")"
  fi

  local dns_bind_ns="${DNSUTILS_OVERRIDE_NS:-127.0.88.53:53}"
  local http_addr="${TEST_HTTP_ADDR:-127.0.0.1}"
  local http_url="${TEST_HTTP_URL:-}"
  if [[ -z "$http_url" ]]; then
    if [[ "$test_dns_kdc" == "1" ]]; then
      http_url="http://cname.test.gokrb5"
    else
      http_url="http://127.0.0.1"
    fi
  fi

  docker_cmd run -d "${platform_args[@]}" -h ns.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -e "TEST_KDC_ADDR=$dns_kdc_addr" \
    -e "TEST_HTTP_ADDR=$http_addr" \
    -p "$dns_bind_ns:53" -p "$dns_bind_ns:53/udp" \
    --name dns jcmturner/gokrb5:dns >/dev/null
  relax_dns_acl

  local dns_ip="${DNS_IP:-}"
  if [[ -z "$dns_ip" ]]; then
    if [[ "$direct" == "1" ]]; then
      dns_ip="$(container_ip dns)"
    else
      dns_ip="${dns_bind_ns%:*}"
    fi
  fi
  local dns_override_ns="${DNSUTILS_OVERRIDE_NS:-"$dns_ip:53"}"

  if [[ "$test_dns_kdc" == "1" || "$http_url" == *".test.gokrb5"* ]]; then
    wait_for_dns_fixture "$dns_override_ns" "$http_addr"
  fi

  write_env \
    "$primary_addr" "$old_addr" "$latest_addr" "$resdom_addr" "$short_addr" \
    "$kpasswd_addr" "$kpasswd_sender_addr" "$dns_ip" "$dns_override_ns" \
    "$http_url" "$http_addr" "$test_dns_kdc"

  configure_resolver "$dns_ip" "$configure_resolver_enabled"
  if [[ "$configure_resolver_enabled" == "1" && "$test_dns_kdc" == "1" ]]; then
    verify_configured_resolver "$http_addr"
  fi

  echo "Started gokrb5 integration fixtures."
  echo "Environment written to $ENV_FILE"
}

run_tests() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE; run '$0 start' first." >&2
    return 1
  fi

  # shellcheck disable=SC1090
  source "$ENV_FILE"
  local configure_resolver_enabled
  configure_resolver_enabled="$(default_configure_resolver_enabled)"
  configure_resolver "$DNS_IP" "$configure_resolver_enabled"
  if [[ "$configure_resolver_enabled" == "1" && "$TEST_DNS_KDC" == "1" ]]; then
    verify_configured_resolver "$TEST_HTTP_ADDR"
  fi
  cargo test --all-features "$@"
}

print_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE; run '$0 start' first." >&2
    return 1
  fi
  cat "$ENV_FILE"
}

main() {
  local command="${1:-}"
  if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
    usage
    exit 0
  fi
  shift || true

  case "$command" in
    start)
      start_fixtures
      ;;
    test)
      run_tests "$@"
      ;;
    run)
      if [[ "${RSKRB5_KEEP_CONTAINERS:-0}" != "1" ]]; then
        trap stop_all EXIT
      fi
      start_fixtures
      run_tests "$@"
      ;;
    stop)
      stop_all
      ;;
    env)
      print_env
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
