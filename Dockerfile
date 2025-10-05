# Intentionally vulnerable Dockerfile for container security testing
FROM python:3.9-slim

# Use root user (vulnerability)
USER root

# Install vulnerable packages
RUN apt-get update && apt-get install -y \
    openssl=1.1.1f-1ubuntu2 \
    curl=7.68.0-1ubuntu2 \
    wget=1.20.3-1ubuntu1 \
    # Don't clean up to keep vulnerable packages
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install vulnerable dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY vulnerable-app.py .

# Run as root (vulnerability)
USER root

# Expose port
EXPOSE 8080

# Start application
CMD ["python", "vulnerable-app.py"]
