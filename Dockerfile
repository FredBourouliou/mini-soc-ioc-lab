FROM python:3.11-slim

# Install system dependencies for YARA
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash scanner

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Change ownership to non-root user
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Default command
ENTRYPOINT ["python", "src/scan_ioc.py"]
CMD ["--help"]