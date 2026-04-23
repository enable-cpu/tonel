# Docker Deployment

This project ships a user-level `systemd` service for running `tonelc` inside a
privileged Docker container on the local machine.

The intended use case is:

- local `tonelc` runs in Docker with `--network host`
- remote `tonels` runs directly on a Linux server
- HY2 or another UDP-speaking client sends traffic to local `tonelc`

## Build The Local Image

Build the image used by `tonelc-docker.service`:

```bash
docker build -t tonel-e2e-local -f tests/e2e/Dockerfile .
```

The image contains:

- Rust toolchain
- `iptables`
- `iproute2`
- `python3`

This lets the container rebuild `tonelc` from the current workspace before
starting it.

## Install The User Service

Install the service and example environment file:

```bash
mkdir -p ~/.config/systemd/user
install -m 0644 deploy/systemd/tonelc-docker.service ~/.config/systemd/user/tonelc-docker.service
install -m 0644 deploy/systemd/tonelc-docker.env.example ~/.config/tonelc-docker.env
systemctl --user daemon-reload
systemctl --user enable --now tonelc-docker.service
```

## Environment File

The service reads `~/.config/tonelc-docker.env`.

Important fields:

- `TONEL_WORKDIR`
  - absolute path to the local Tonel workspace mounted into the container
- `TONEL_DOCKER_IMAGE`
  - Docker image name, defaults to `tonel-e2e-local`
- `PROXY_URL`
  - optional local HTTP proxy for dependency download during container builds
- `TONELC_ARGS`
  - final command-line flags passed to `tonelc`

Example:

```bash
TONEL_WORKDIR=/home/qs/workspace/github/tonel
TONEL_DOCKER_IMAGE=tonel-e2e-local
PROXY_URL=http://127.0.0.1:7890
TONELC_ARGS=-4 --local 127.0.0.1:1111 --remote 52.76.22.225:2222 --tcp-connections 3 --auto-rule eno1 --log-level debug
```

## Runtime Model

`tonelc-docker.service` runs:

- `docker run --network host --privileged`

This is required because `tonelc` needs to:

- create and manage a TUN device
- install and remove firewall rules
- bind the host UDP port directly

Even though `tonelc` runs in Docker, the listener is on the host network
namespace. For example, if `TONELC_ARGS` contains `--local 127.0.0.1:1111`,
local HY2 should target `127.0.0.1:1111`.

## Verification

Check service state:

```bash
systemctl --user status tonelc-docker.service
docker ps --format 'table {{.Names}}\t{{.Status}}'
docker logs --since 20s tonelc-service
```

Check whether `tonelc` is listening on the expected UDP port:

```bash
docker exec tonelc-service sh -lc "ss -lun | grep 127.0.0.1:1111"
```

## Troubleshooting

- `failed to connect to the docker API at unix:///var/run/docker.sock`
  - local Docker daemon is not running
- `bind: address already in use`
  - another process is already using the configured local port
- HY2 client cannot reach local `tonelc`
  - if HY2 is running on the host, `127.0.0.1:1111` is valid
  - if HY2 is running in another container or namespace, do not use `127.0.0.1`
- Rebuild with current code after changes:

```bash
systemctl --user restart tonelc-docker.service
```
