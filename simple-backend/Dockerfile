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

# Create non-root user and writable data directory
RUN groupadd --gid 1001 appuser \
    && useradd --uid 1001 --gid appuser --shell /bin/false appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data

# Expose port
EXPOSE 5001

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

# Run with gunicorn — single worker + threads for shared memory, generous timeout
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "1", "--threads", "4", "--timeout", "300", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
