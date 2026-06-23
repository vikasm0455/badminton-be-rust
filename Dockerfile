# Stage 1: build the Rust API
FROM rust:1.88 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
# Migrations are embedded into the binary at compile time (sqlx::migrate!),
# so the runtime image doesn't need the migrations dir.
RUN cargo build --release --bin rallyup-api --bin reset-admin-otp

# Final image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/rallyup-api /usr/local/bin/rallyup-api
COPY --from=builder /app/target/release/reset-admin-otp /usr/local/bin/reset-admin-otp

ENV TZ=America/Los_Angeles
EXPOSE 8090
CMD ["rallyup-api"]
