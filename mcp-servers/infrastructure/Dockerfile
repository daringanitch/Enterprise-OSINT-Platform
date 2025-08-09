FROM python:3.11-slim

WORKDIR /app

# Install minimal dependencies
RUN pip install flask requests

# Copy application
COPY app.py .

# Expose port
EXPOSE 8020

# Run application
CMD ["python", "app.py"]