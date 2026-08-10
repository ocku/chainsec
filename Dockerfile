# syntax=docker/dockerfile:1

FROM rust:1.89.0-bookworm AS builder
WORKDIR /build

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release \
    && strip target/release/chainsec

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin chainsec \
    && install --directory --owner chainsec --group chainsec /scan /cache

COPY --from=builder /build/target/release/chainsec /usr/local/bin/chainsec

USER chainsec
WORKDIR /scan

ENTRYPOINT ["chainsec"]
CMD ["--help"]
