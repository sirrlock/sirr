# ── Builder ────────────────────────────────────────────────────────────────────
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev && \
    rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/

# Build a static musl binary.
# Alpine is already musl — point cargo at the native gcc instead of the
# missing cross-linker x86_64-linux-musl-gcc.
RUN CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc \
    cargo build --release --bin sirrd --target x86_64-unknown-linux-musl

# ── Final image ────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/sirrd /sirrd

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
