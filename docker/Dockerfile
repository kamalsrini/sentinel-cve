FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY sentinel/ sentinel/

RUN pip install --no-cache-dir -e ".[server]"

# Run as non-root user for security
RUN adduser --disabled-password --no-create-home --gecos "" sentinel
USER sentinel

EXPOSE 8080

CMD ["uvicorn", "sentinel.server:app", "--host", "0.0.0.0", "--port", "8080"]
