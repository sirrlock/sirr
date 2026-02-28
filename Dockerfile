# ── Builder ────────────────────────────────────────────────────────────────────
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/

# Alpine is already musl-based, so the default target produces a static musl
# binary without needing cross-compilation or --target flags.
RUN cargo build --release --bin sirrd

# ── Final image ────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /build/target/release/sirrd /sirrd

# Data directory — mount a volume here for persistence.
VOLUME ["/data"]

# Key file directory — mount a read-only volume here for file-based key delivery.
# Preferred over SIRR_MASTER_KEY env var in production (env vars are visible via
# docker inspect and /proc).
VOLUME ["/run/secrets"]

ENV SIRR_DATA_DIR=/data \
    SIRR_HOST=0.0.0.0 \
    SIRR_PORT=8080

EXPOSE 8080

ENTRYPOINT ["/sirrd"]
CMD ["serve"]
