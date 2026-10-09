# Multi-stage container with OpenJDK 17 + Python 3.11 for JADX & FastAPI
FROM eclipse-temurin:17-jdk-jammy AS java-base

# Install Python 3.11 & utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project code
COPY . .

# Environment variables
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python3", "run.py", "serve", "--port", "8000", "--host", "0.0.0.0"]
