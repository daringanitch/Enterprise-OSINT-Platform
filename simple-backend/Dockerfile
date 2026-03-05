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

# Health check — give 60 s for eventlet worker + all blueprint imports to load
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

# Run with gunicorn + eventlet worker (required by flask-socketio async_mode='eventlet').
# Using the default gthread worker causes gunicorn to hang before binding port 5001
# when eventlet is installed alongside flask-socketio.
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--worker-class", "eventlet", \
     "--workers", "1", "--timeout", "300", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
