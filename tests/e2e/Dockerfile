FROM docker.m.daocloud.io/library/rust:1.78

RUN printf '%s\n' \
        'Types: deb' \
        'URIs: https://mirrors.ustc.edu.cn/debian' \
        'Suites: bookworm bookworm-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        '' \
        'Types: deb' \
        'URIs: https://mirrors.ustc.edu.cn/debian-security' \
        'Suites: bookworm-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        >/etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        make \
        netcat-openbsd \
        procps \
        python3 \
    && rm -rf /var/lib/apt/lists/*
