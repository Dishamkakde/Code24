FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies for git import and health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies including Semgrep and Bandit
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application
COPY backend/ /app/backend/

# Copy compiled frontend assets for web UI
COPY frontend/dist/ /app/frontend/dist/

# Set working directory to backend
WORKDIR /app/backend

# Create storage directory for SQLite database and extracted projects
RUN mkdir -p /app/backend/storage/projects /app/backend/storage/temp

EXPOSE 8000

# Health check against API health endpoint
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Default command: run FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
