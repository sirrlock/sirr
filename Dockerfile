# ── Builder ────────────────────────────────────────────────────────────────────
FROM rust:1.78-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/

# Build a static musl binary.
RUN cargo build --release --bin sirr --target x86_64-unknown-linux-musl

# ── Final image ────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/sirr /sirr

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

ENTRYPOINT ["/sirr"]
CMD ["serve"]
