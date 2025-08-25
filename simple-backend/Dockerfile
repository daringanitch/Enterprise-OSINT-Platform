FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY models.py .
COPY investigation_orchestrator.py .
COPY mcp_clients.py .
COPY compliance_framework.py .
COPY investigation_reporting.py .
COPY risk_assessment_engine.py .
COPY vault_client.py .
COPY professional_report_generator.py .
COPY audit_report_generator.py .
COPY postgres_audit_client.py .
COPY api_connection_monitor.py .
COPY job_queue.py .
COPY problem_json.py .
COPY structured_logging.py .
COPY trace_context.py .
COPY observability.py .

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]