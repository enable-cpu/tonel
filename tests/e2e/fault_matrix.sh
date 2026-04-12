#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-tonel-e2e:local}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/target/e2e}"
CARGO_CACHE_DIR="${CARGO_CACHE_DIR:-/tmp/cargo-tonel}"
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$CARGO_CACHE_DIR"

SCENARIOS=(
  "baseline||||||"
  "delay_jitter|delay 120ms 20ms distribution normal|delay 120ms 20ms distribution normal|--timeout-ms 1800|||"
  "mild_loss|loss 3%|loss 3%|--attempts 10 --timeout-ms 1500|||"
  "reorder_duplicate|delay 80ms 10ms reorder 10% 50% duplicate 1%|delay 80ms 10ms reorder 10% 50% duplicate 1%|--attempts 10 --timeout-ms 1500|||"
  "asymmetric_client_egress|delay 120ms 20ms loss 5%||--attempts 10 --timeout-ms 1800|||"
  "asymmetric_server_egress||delay 120ms 20ms loss 5%|--attempts 10 --timeout-ms 1800|||"
  "brief_client_blackhole|||--attempts 20 --timeout-ms 1500 --start-delay-ms 300|client:loss 100%:1.5|||"
  "brief_server_blackhole|||--attempts 20 --timeout-ms 1500 --start-delay-ms 300|server:loss 100%:1.5|||"
  "idle_gap_under_threshold|||--messages 4 --attempts 12 --timeout-ms 1500 --pause-between-messages-ms 5000|||"
  "large_payload_loss_jitter|delay 80ms 10ms loss 2%|delay 80ms 10ms loss 2%|--messages 24 --attempts 12 --timeout-ms 2200 --pause-between-messages-ms 80 --payload-size 1400|||"
  "soak_loss_jitter|delay 60ms 15ms loss 2%|delay 60ms 15ms loss 2%|--messages 120 --attempts 10 --timeout-ms 1500 --pause-between-messages-ms 100|||"
  "server_restart_recovery|delay 40ms 10ms loss 1%|delay 60ms 20ms loss 2% reorder 10%|--messages 40 --attempts 12 --timeout-ms 2000 --pause-between-messages-ms 80 --payload-size 128|||server_restart:3:3"
  "composite_combo|delay 90ms 25ms distribution normal loss 5% reorder 20% 45% duplicate 3% corrupt 0.1%|delay 60ms 15ms loss 4% reorder 15% 30% duplicate 2% corrupt 0.2%|--messages 60 --attempts 12 --timeout-ms 2200 --pause-between-messages-ms 60 --payload-size 256|||"
  "negative_assert_loss|delay 100ms loss 40%|delay 100ms loss 40%|--messages 24 --attempts 8 --timeout-ms 800 --start-delay-ms 100 --max-average-attempts 2.5 --max-total-duration-ms 1500||expect_failure|"
)

TRANSIENT_PID=""
EVENT_PID=""

cleanup() {
  local client_name="${1:-}"
  local server_name="${2:-}"
  local network_name="${3:-}"
  if [[ -n "$TRANSIENT_PID" ]]; then
    kill "$TRANSIENT_PID" >/dev/null 2>&1 || true
    wait "$TRANSIENT_PID" >/dev/null 2>&1 || true
    TRANSIENT_PID=""
  fi
  if [[ -n "$EVENT_PID" ]]; then
    kill "$EVENT_PID" >/dev/null 2>&1 || true
    wait "$EVENT_PID" >/dev/null 2>&1 || true
    EVENT_PID=""
  fi
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
  docker exec "$container_name" sh -lc "tc qdisc show dev eth0 | grep -q netem"
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

start_event() {
  local spec="$1"
  local client_name="$2"
  local server_name="$3"
  local client_fault_rule="$4"
  local server_fault_rule="$5"
  EVENT_PID=""
  if [[ -z "$spec" ]]; then
    return
  fi

  IFS=':' read -r event_type delay_s down_s <<<"$spec"
  delay_s="${delay_s:-0}"
  down_s="${down_s:-0}"

  (
    sleep "$delay_s"
    case "$event_type" in
      server_restart)
        docker stop -t 1 "$server_name" >/dev/null 2>&1 || true
        sleep "$down_s"
        docker start "$server_name" >/dev/null
        wait_for_server "$server_name"
        apply_fault "$server_name" "$server_fault_rule"
        ;;
      client_restart)
        docker stop -t 1 "$client_name" >/dev/null 2>&1 || true
        sleep "$down_s"
        docker start "$client_name" >/dev/null
        wait_for_client "$client_name"
        apply_fault "$client_name" "$client_fault_rule"
        ;;
      *)
        echo "unknown event type: $event_type" >&2
        exit 1
        ;;
    esac
  ) &
  EVENT_PID=$!
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

collect_artifacts() {
  local scenario_dir="$1"
  local client_name="$2"
  local server_name="$3"
  docker logs "$client_name" >"$scenario_dir/client.log" 2>&1 || true
  docker logs "$server_name" >"$scenario_dir/server.log" 2>&1 || true
  docker exec "$client_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/client-tc.log" 2>&1 || true
  docker exec "$server_name" sh -lc "tc qdisc show dev eth0" >"$scenario_dir/server-tc.log" 2>&1 || true
}

run_scenario() {
  local scenario_name="$1"
  local client_fault_rule="$2"
  local server_fault_rule="$3"
  local probe_args="$4"
  local transient_fault="$5"
  local expect="$6"
  local event_spec="$7"
  local network_name="tonel-e2e-${scenario_name}-$$"
  local client_name="${network_name}-client"
  local server_name="${network_name}-server"
  local scenario_dir="$ARTIFACT_DIR/$scenario_name"
  mkdir -p "$scenario_dir"

  local expect_failure=0
  if [[ "$expect" == "expect_failure" ]]; then
    expect_failure=1
  fi

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
  start_event "$event_spec" "$client_name" "$server_name" "$client_fault_rule" "$server_fault_rule"
  local event_pid="$EVENT_PID"

  set +e
  docker exec "$client_name" python3 /work/tests/e2e/udp_roundtrip.py --target 127.0.0.1:1111 $probe_args
  local probe_exit=$?
  set -e

  if [[ -n "$transient_pid" ]]; then
    wait "$transient_pid" || true
    TRANSIENT_PID=""
  fi
  if [[ -n "$event_pid" ]]; then
    if ! wait "$event_pid"; then
      echo "event '$event_spec' failed for scenario '$scenario_name'" >&2
      exit 1
    fi
    EVENT_PID=""
  fi

  collect_artifacts "$scenario_dir" "$client_name" "$server_name"

  if [[ $expect_failure -eq 1 ]]; then
    if [[ $probe_exit -eq 0 ]]; then
      echo "scenario '$scenario_name' unexpectedly succeeded; expected failure" >&2
      exit 1
    fi
    echo "scenario '$scenario_name' failed as expected (exit $probe_exit)"
  else
    if [[ $probe_exit -ne 0 ]]; then
      echo "scenario '$scenario_name' failed; logs saved to $scenario_dir" >&2
      exit 1
    fi
  fi

  trap - RETURN
  cleanup "$client_name" "$server_name" "$network_name"
}

main() {
  build_image
  build_binaries
  for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario_name client_fault_rule server_fault_rule probe_args transient_fault expect event <<<"$entry"
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
    run_scenario "$scenario_name" "$client_fault_rule" "$server_fault_rule" "$probe_args" "$transient_fault" "$expect" "$event"
  done
}

main "$@"
