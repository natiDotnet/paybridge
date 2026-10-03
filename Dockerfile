FROM rust:1.99-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --features pg --bin paybridge

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home paybridge

WORKDIR /app
COPY --from=builder /app/target/release/paybridge /usr/local/bin/paybridge
COPY --from=builder /app/static /app/static

ENV PAYBRIDGE_BIND=0.0.0.0:4000 \
    PAYBRIDGE_STATIC_DIR=/app/static

USER 10001:10001
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/paybridge"]