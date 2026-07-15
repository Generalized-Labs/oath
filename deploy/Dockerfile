# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.94.0
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release --locked -p oath-registry

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 oath \
    && useradd --uid 10001 --gid oath --no-create-home --home-dir /nonexistent oath \
    && install --directory --owner oath --group oath /var/lib/oath-registry

COPY --from=builder /src/target/release/oath-registry /usr/local/bin/oath-registry

ENV OATH_REGISTRY_BIND=0.0.0.0:4873 \
    OATH_REGISTRY_DATA=/var/lib/oath-registry \
    RUST_LOG=oath_registry=info,tower_http=info

USER 10001:10001
EXPOSE 4873
VOLUME ["/var/lib/oath-registry"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:4873/livez"]

ENTRYPOINT ["/usr/local/bin/oath-registry"]
