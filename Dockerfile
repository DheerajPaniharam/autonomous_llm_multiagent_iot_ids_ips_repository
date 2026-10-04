FROM python:3.11-slim

WORKDIR /app

# Ensure application package directory is on Python path for tests and runtime
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY traffic_capture/ ./traffic_capture/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create state directory for firewall rule persistence
RUN mkdir -p state

# Expose API port
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
