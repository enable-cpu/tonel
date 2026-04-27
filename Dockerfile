ARG RUST_VERSION=1.78

FROM rust:${RUST_VERSION} AS builder
WORKDIR /work

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --bin tonelc --bin tonels

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

FROM runtime AS tonelc
COPY --from=builder /work/target/release/tonelc /usr/local/bin/tonelc
ENTRYPOINT ["/usr/local/bin/tonelc"]

FROM runtime AS tonels
COPY --from=builder /work/target/release/tonels /usr/local/bin/tonels
ENTRYPOINT ["/usr/local/bin/tonels"]
