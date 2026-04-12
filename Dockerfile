# ── Builder ────────────────────────────────────────────────────────────────────
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/

RUN cargo build --release --bin sirrd

# ── Final image ────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /build/target/release/sirrd /sirrd

VOLUME ["/data"]

ENV SIRR_DATA_DIR=/data

EXPOSE 7843

ENTRYPOINT ["/sirrd"]
CMD ["serve", "--bind", "0.0.0.0:7843", "--data-dir", "/data", "--admin-socket", "/data/sirrd.sock"]
