FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── GeoLite2 database ─────────────────────────────────────────────────────────
# GeoIP is resolved in-process from this file so investigation target IPs never
# leave the host. MaxMind's licence forbids redistribution, so the database is
# NOT committed — it is fetched here with your own licence key:
#
#   docker build --build-arg MAXMIND_LICENSE_KEY=xxxx -t mcp-infrastructure .
#
# Get a free key at https://www.maxmind.com/en/geolite2/signup. Without one the
# image still builds and the server still runs; GeoIP lookups report themselves
# unavailable rather than falling back to any network service.
#
# The database ships inside the image because the Kubernetes deployment sets
# readOnlyRootFilesystem: true. Rebuild to refresh it (MaxMind updates weekly),
# or mount a newer file over /app/geoip and point GEOIP_DB_PATH at it.
ARG MAXMIND_LICENSE_KEY=""
RUN mkdir -p /app/geoip && \
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      curl -fsSL -o /tmp/geolite2.tar.gz \
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" && \
      tar -xzf /tmp/geolite2.tar.gz -C /tmp && \
      find /tmp -name 'GeoLite2-City.mmdb' -exec mv {} /app/geoip/ \; && \
      rm -rf /tmp/geolite2.tar.gz /tmp/GeoLite2-City_* && \
      echo "GeoLite2 database installed"; \
    else \
      echo "WARNING: MAXMIND_LICENSE_KEY not supplied — GeoIP lookups will be unavailable"; \
    fi

ENV GEOIP_DB_PATH=/app/geoip/GeoLite2-City.mmdb

# Copy application code
COPY app.py geoip_local.py passive_dns_circl.py cert_chain.py ./

# Create non-root user
RUN useradd -m -u 1000 mcp && chown -R mcp:mcp /app
USER mcp

# MCP server port
EXPOSE 5015

# Run the MCP server
CMD ["python", "app.py"]
