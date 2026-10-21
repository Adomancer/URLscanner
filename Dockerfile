# OSINT URL Scanner — runs the web UI with gunicorn as a non-root user.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user; keep the scan database on a writable volume.
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /app/outputs \
    && chown -R scanner:scanner /app
USER scanner

ENV SCANNER_OUTPUT_DIR=/app/outputs \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

EXPOSE 5000
VOLUME ["/app/outputs"]

# 2 workers, 4 threads each: scans are I/O-bound (network), so threads help.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", \
     "--timeout", "120", "webapp:app"]
