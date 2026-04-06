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
    args = parser.parse_args()

    host, port = args.target.rsplit(":", 1)
    target = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)

    if args.start_delay_ms > 0:
        time.sleep(args.start_delay_ms / 1000.0)

    for message_id in range(args.messages):
        body = secrets.token_bytes(max(0, args.payload_size - 4))
        payload = struct.pack("!I", message_id) + body
        matched = False
        for _ in range(args.attempts):
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

        if args.pause_between_messages_ms > 0 and message_id + 1 < args.messages:
            time.sleep(args.pause_between_messages_ms / 1000.0)


if __name__ == "__main__":
    main()
