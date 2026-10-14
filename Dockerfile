# ==============================================================================
# Exactor WAF Guardian - Production Docker Container
# Multi-Stage Ultra-Fast Build
# ==============================================================================

FROM rust:1.80-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace cargo files and source
COPY . .

# Build release binary
RUN cargo build --release --bin exactor-waf-guardian

# --- Runtime Stage ---
FROM debian:bookworm-slim

WORKDIR /etc/exactor

# Install runtime dependencies (OpenSSL & CA certificates for https://exactor.tech)
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Copy executable and default configuration
COPY --from=builder /usr/src/app/target/release/exactor-waf-guardian /usr/local/bin/exactor-waf-guardian
COPY waf_config.toml /etc/exactor/waf_config.toml

# Expose HTTP proxy & API port
EXPOSE 8080

# Environment variables
ENV WAF_LISTEN_ADDR="0.0.0.0:8080"
ENV WAF_UPSTREAM_URL="http://127.0.0.1:3000"
ENV WAF_MODE="block"
ENV EXACTOR_API_URL="https://exactor.tech/api/simplify"
ENV WAF_DATABASE_PATH="/etc/exactor/waf_ledger.db"

# Healthcheck
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/exactor-waf-guardian", "proxy", "--config", "/etc/exactor/waf_config.toml"]
