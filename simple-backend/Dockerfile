FROM python:3.11-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source — copy all required directories and files
COPY blueprints/      ./blueprints/
COPY graph_intelligence/ ./graph_intelligence/
COPY utils/           ./utils/
COPY *.py             ./

# Runtime data directory (overridden by APP_DATA_DIR env var in compose)
RUN mkdir -p /app/data

# Expose port
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

# Run with gunicorn — 2 workers, generous timeout for intelligence ops
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--timeout", "120", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
