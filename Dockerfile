# Multi-stage relay image for PaaS (Railway, Fly, etc.).
# Copies a release binary into a minimal glibc runtime so `./target/release/...`
# does not disappear between build and run, and Alpine/musl "No such file" issues are avoided.

# syntax=docker/dockerfile:1

FROM rust:1.89-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p beam-relay --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/beam-relay /usr/local/bin/beam-relay

# Railway injects PORT at runtime.
CMD ["sh", "-c", "exec beam-relay --listen 0.0.0.0:${PORT:-8787}"]
