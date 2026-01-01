# =============================================================================
# User Management API - Dockerfile
# =============================================================================
# Multi-stage build for optimized production image
# - Stage 1 (builder): Compiles the Rust application
# - Stage 2 (runtime): Minimal runtime image with the compiled binary
# =============================================================================

# -----------------------------------------------------------------------------
# Build Stage
# -----------------------------------------------------------------------------
FROM rust:1.83-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty shell project
WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source file to build dependencies
# This layer will be cached as long as Cargo.toml/Cargo.lock don't change
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the application (touch to invalidate the dummy main.rs)
RUN touch src/main.rs && cargo build --release

# -----------------------------------------------------------------------------
# Runtime Stage
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

# Labels for container metadata
LABEL maintainer="API Support <support@example.com>"
LABEL description="User Management API - REST API for user authentication and management"
LABEL version="1.0.0"

# Install runtime dependencies
# - ca-certificates: For HTTPS connections
# - libssl3: OpenSSL runtime library
# - curl: For health checks
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/user_management ./user_management

# Create uploads directory with proper permissions
RUN mkdir -p uploads && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8080

# -----------------------------------------------------------------------------
# Environment Variables (defaults for container)
# -----------------------------------------------------------------------------
# Logging
ENV RUST_LOG=info

# Server configuration
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080

# Upload directory (inside container)
ENV UPLOAD_DIR=/app/uploads

# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------
# Check if the API health endpoint is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
CMD ["./user_management"]

