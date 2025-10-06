FROM python:3.11-slim

WORKDIR /app

# Install Docker CLI and dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code
COPY hackbox_server.py .

# Create a non-root user
RUN useradd -m -u 1000 hackbox
USER hackbox

# Expose port for HTTP transport (optional)
EXPOSE 8000

# Run the server
CMD ["python", "hackbox_server.py"]
