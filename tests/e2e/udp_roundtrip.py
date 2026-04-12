#!/usr/bin/env python3
import argparse
import secrets
import socket
import struct
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="HOST:PORT")
    parser.add_argument("--messages", type=int, default=16)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--timeout-ms", type=int, default=1200)
    parser.add_argument("--payload-size", type=int, default=96)
    parser.add_argument("--pause-ms", type=int, default=20)
    parser.add_argument("--pause-between-messages-ms", type=int, default=0)
    parser.add_argument("--start-delay-ms", type=int, default=0)
    parser.add_argument("--max-average-attempts", type=float)
    parser.add_argument("--max-total-duration-ms", type=float)
    parser.add_argument("--expect-min-message-duration-ms", type=float)
    args = parser.parse_args()

    host, port = args.target.rsplit(":", 1)
    target = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)

    if args.start_delay_ms > 0:
        time.sleep(args.start_delay_ms / 1000.0)

    attempts_per_message = []
    start_time = time.monotonic()
    max_message_duration_ms = 0.0

    for message_id in range(args.messages):
        body = secrets.token_bytes(max(0, args.payload_size - 4))
        payload = struct.pack("!I", message_id) + body
        matched = False
        attempts_for_message = 0
        message_start = time.monotonic()
        for attempt_index in range(args.attempts):
            attempts_for_message = attempt_index + 1
            sock.sendto(payload, target)
            try:
                response, _ = sock.recvfrom(65535)
            except socket.timeout:
                time.sleep(args.pause_ms / 1000.0)
                continue

            if response == payload:
                matched = True
                break

        if not matched:
            raise SystemExit(f"roundtrip failed for message {message_id}")

        attempts_per_message.append(attempts_for_message)
        message_duration_ms = (time.monotonic() - message_start) * 1000
        if message_duration_ms > max_message_duration_ms:
            max_message_duration_ms = message_duration_ms
        if args.pause_between_messages_ms > 0 and message_id + 1 < args.messages:
            time.sleep(args.pause_between_messages_ms / 1000.0)
    total_duration_ms = (time.monotonic() - start_time) * 1000
    avg_attempts = sum(attempts_per_message) / len(attempts_per_message)
    max_attempts = max(attempts_per_message)
    summary = (
        f"stats: messages={args.messages} avg_attempts={avg_attempts:.2f} "
        f"max_attempts={max_attempts} max_message_duration_ms={max_message_duration_ms:.0f} "
        f"total_duration_ms={total_duration_ms:.0f}"
    )
    print(summary)

    if args.max_average_attempts is not None and avg_attempts > args.max_average_attempts:
        raise SystemExit(
            f"average attempts {avg_attempts:.2f} exceeds configured limit {args.max_average_attempts}"
        )
    if args.max_total_duration_ms is not None and total_duration_ms > args.max_total_duration_ms:
        raise SystemExit(
            f"total duration {total_duration_ms:.0f}ms exceeds configured limit {args.max_total_duration_ms}ms"
        )
    if (
        args.expect_min_message_duration_ms is not None
        and max_message_duration_ms < args.expect_min_message_duration_ms
    ):
        raise SystemExit(
            f"max message duration {max_message_duration_ms:.0f}ms is below expected "
            f"threshold {args.expect_min_message_duration_ms}ms"
        )


if __name__ == "__main__":
    main()
