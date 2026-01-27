# syntax=docker/dockerfile:1
FROM rust:1.83-slim AS builder

WORKDIR /app

# Build deps for openssl-sys
RUN apt-get update \
  && apt-get install -y --no-install-recommends pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Build deps layer
COPY Cargo.toml Cargo.toml
COPY src src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV BIND_ADDR=0.0.0.0:3000

COPY --from=builder /app/target/release/nostr_proxy /usr/local/bin/nostr-proxy

EXPOSE 3000

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/nostr-proxy"]
