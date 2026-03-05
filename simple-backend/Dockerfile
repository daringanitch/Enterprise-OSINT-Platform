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

# Health check — 60 s start_period gives gunicorn time to load all blueprints
# before the first check fires. flask-socketio does NOT call monkey_patch(), so
# gthread workers are safe and stable here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health')" || exit 1

# Run with gunicorn gthread workers (1 process, 4 threads for shared in-process
# state). flask-socketio's eventlet async_mode applies only to the Socket.IO
# event loop, not to gunicorn's worker class — gthread is correct here.
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "1", "--threads", "4", \
     "--timeout", "300", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
