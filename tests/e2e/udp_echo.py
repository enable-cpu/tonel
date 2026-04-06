#!/usr/bin/env python3
import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True, help="HOST:PORT")
    args = parser.parse_args()

    host, port = args.bind.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))

    while True:
        payload, peer = sock.recvfrom(65535)
        sock.sendto(payload, peer)


if __name__ == "__main__":
    main()
