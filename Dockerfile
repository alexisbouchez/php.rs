# Dockerfile for php.rs - PHP interpreter written in Rust
# Build: docker build -t php-rs .
# Run: docker run -it --rm php-rs

FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary
RUN cargo build --release -p php-rs-sapi-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/php-rs /usr/local/bin/php-rs

# Create directory for PHP scripts
WORKDIR /var/www

# Set php-rs as entrypoint
ENTRYPOINT ["php-rs"]

# Default: show help
CMD ["--help"]
