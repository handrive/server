# Build stage
FROM rust:1.93-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY server ./server

# Build the application
RUN cargo build --release --package handrive-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 handrive \
    && useradd --uid 1000 --gid handrive --shell /bin/bash --create-home handrive

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/handrive-server /app/handrive-server

# Copy migrations
COPY --from=builder /app/server/migrations /app/migrations

# Create log directory and set ownership
RUN mkdir -p /var/log/handrive && chown -R handrive:handrive /var/log/handrive /app

# Switch to non-root user
USER handrive

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

CMD ["/app/handrive-server"]
