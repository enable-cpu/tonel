#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-tonel-e2e:local}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/target/e2e}"
CARGO_CACHE_DIR="${CARGO_CACHE_DIR:-/tmp/cargo-tonel}"
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$CARGO_CACHE_DIR"

SCENARIOS=(
  "baseline||||"
  "delay_jitter|delay 120ms 20ms distribution normal|delay 120ms 20ms distribution normal|--timeout-ms 1800|"
  "mild_loss|loss 3%|loss 3%|--attempts 10 --timeout-ms 1500|"
  "reorder_duplicate|delay 80ms 10ms reorder 10% 50% duplicate 1%|delay 80ms 10ms reorder 10% 50% duplicate 1%|--attempts 10 --timeout-ms 1500|"
  "asymmetric_client_egress|delay 120ms 20ms loss 5%||--attempts 10 --timeout-ms 1800|"
  "asymmetric_server_egress||delay 120ms 20ms loss 5%|--attempts 10 --timeout-ms 1800|"
  "brief_client_blackhole|||--attempts 20 --timeout-ms 1500 --start-delay-ms 300|client:loss 100%:1.5"
  "brief_server_blackhole|||--attempts 20 --timeout-ms 1500 --start-delay-ms 300|server:loss 100%:1.5"
  "idle_gap_under_threshold|||--messages 4 --attempts 12 --timeout-ms 1500 --pause-between-messages-ms 5000|"
  "soak_loss_jitter|delay 60ms 15ms loss 2%|delay 60ms 15ms loss 2%|--messages 120 --attempts 10 --timeout-ms 1500 --pause-between-messages-ms 100|"
)

TRANSIENT_PID=""

cleanup() {
  local client_name="${1:-}"
  local server_name="${2:-}"
  local network_name="${3:-}"
  if [[ -n "$client_name" ]]; then
    docker rm -f "$client_name" >/dev/null 2>&1 || true
  fi
  if [[ -n "$server_name" ]]; then
    docker rm -f "$server_name" >/dev/null 2>&1 || true
  fi
  if [[ -n "$network_name" ]]; then
    docker network rm "$network_name" >/dev/null 2>&1 || true
  fi
}

apply_fault() {
  local container_name="$1"
  local rule="$2"
  if [[ -z "$rule" ]]; then
    return
  fi
  docker exec "$container_name" tc qdisc replace dev eth0 root netem $rule
}

clear_fault() {
  local container_name="$1"
  docker exec "$container_name" tc qdisc del dev eth0 root >/dev/null 2>&1 || true
}

start_transient_fault() {
  local client_name="$1"
  local server_name="$2"
  local spec="$3"
  TRANSIENT_PID=""
  if [[ -z "$spec" ]]; then
    return
  fi

  IFS=':' read -r target rule duration_s <<<"$spec"
  local container_name
  case "$target" in
    client) container_name="$client_name" ;;
    server) container_name="$server_name" ;;
    *)
      echo "unknown transient fault target: $target" >&2
      exit 1
      ;;
  esac

  (
    apply_fault "$container_name" "$rule"
    sleep "$duration_s"
    clear_fault "$container_name"
  ) &
  TRANSIENT_PID=$!
}

wait_for_client() {
  local container_name="$1"
  for _ in $(seq 1 40); do
    if docker exec "$container_name" sh -lc "ss -lun | grep -q '127.0.0.1:1111'"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_server() {
  local container_name="$1"
  for _ in $(seq 1 40); do
    if docker logs "$container_name" 2>&1 | grep -q 'Listening on 2222'; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

build_image() {
  docker build -t "$IMAGE_TAG" -f "$ROOT_DIR/tests/e2e/Dockerfile" "$ROOT_DIR"
}

build_binaries() {
  local cargo_args=(build --release --locked --verbose --bin tonelc --bin tonels)
  if [[ -d "$CARGO_CACHE_DIR/registry/index" || -d "$CARGO_CACHE_DIR/registry/cache" ]]; then
    cargo_args=(build --offline --release --locked --verbose --bin tonelc --bin tonels)
  fi
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e CARGO_NET_RETRY=10 \
    -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -e RUSTUP_HOME=/usr/local/rustup \
    -e CARGO_HOME=/tmp/cargo \
    -v "$CARGO_CACHE_DIR:/tmp/cargo" \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$IMAGE_TAG" \
    cargo "${cargo_args[@]}"
}

run_scenario() {
  local scenario_name="$1"
  local client_fault_rule="$2"
  local server_fault_rule="$3"
  local probe_args="$4"
  local transient_fault="$5"
  local network_name="tonel-e2e-${scenario_name}-$$"
  local client_name="${network_name}-client"
  local server_name="${network_name}-server"
  local scenario_dir="$ARTIFACT_DIR/$scenario_name"
  mkdir -p "$scenario_dir"

  cleanup "$client_name" "$server_name" "$network_name"
  trap 'cleanup "$client_name" "$server_name" "$network_name"' RETURN

  docker network create "$network_name" >/dev/null

  docker run -d \
    --name "$server_name" \
    --hostname server \
    --network "$network_name" \
    --privileged \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$IMAGE_TAG" \
    /bin/sh -lc \
    "python3 /work/tests/e2e/udp_echo.py --bind 127.0.0.1:3333 >/tmp/udp-echo.log 2>&1 & exec /work/target/release/tonels -4 --local 2222 --remote 127.0.0.1:3333 --auto-rule eth0 --log-level debug" \
    >/dev/null

  docker run -d \
    --name "$client_name" \
    --hostname client \
    --network "$network_name" \
    --privileged \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$IMAGE_TAG" \
    /bin/sh -lc \
    "exec /work/target/release/tonelc -4 --local 127.0.0.1:1111 --remote server:2222 --tcp-connections 2 --auto-rule eth0 --log-level debug" \
    >/dev/null

  wait_for_server "$server_name"
  wait_for_client "$client_name"

  apply_fault "$client_name" "$client_fault_rule"
  apply_fault "$server_name" "$server_fault_rule"

  local transient_pid=""
  if [[ -n "$transient_fault" ]]; then
    start_transient_fault "$client_name" "$server_name" "$transient_fault"
    transient_pid="$TRANSIENT_PID"
  fi

  if ! docker exec "$client_name" python3 /work/tests/e2e/udp_roundtrip.py --target 127.0.0.1:1111 $probe_args; then
    if [[ -n "$transient_pid" ]]; then
      wait "$transient_pid" || true
    fi
    docker logs "$client_name" >"$scenario_dir/client.log" 2>&1 || true
    docker logs "$server_name" >"$scenario_dir/server.log" 2>&1 || true
    docker exec "$client_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/client-tc.log" 2>&1 || true
    docker exec "$server_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/server-tc.log" 2>&1 || true
    echo "scenario '$scenario_name' failed; logs saved to $scenario_dir" >&2
    exit 1
  fi

  if [[ -n "$transient_pid" ]]; then
    wait "$transient_pid"
  fi

  docker logs "$client_name" >"$scenario_dir/client.log" 2>&1 || true
  docker logs "$server_name" >"$scenario_dir/server.log" 2>&1 || true
  docker exec "$client_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/client-tc.log" 2>&1 || true
  docker exec "$server_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/server-tc.log" 2>&1 || true
  trap - RETURN
  cleanup "$client_name" "$server_name" "$network_name"
}

main() {
  build_image
  build_binaries
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario_name client_fault_rule server_fault_rule probe_args transient_fault <<<"$entry"
    if [[ "$#" -gt 0 ]]; then
      local selected=0
      for requested in "$@"; do
        if [[ "$requested" == "$scenario_name" ]]; then
          selected=1
          break
        fi
      done
      if [[ "$selected" -eq 0 ]]; then
        continue
      fi
    fi
    echo "==> scenario: $scenario_name"
    run_scenario "$scenario_name" "$client_fault_rule" "$server_fault_rule" "$probe_args" "$transient_fault"
  done
}

main "$@"
