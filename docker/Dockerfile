FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY sentinel/ sentinel/

RUN pip install --no-cache-dir -e ".[server]"

EXPOSE 8080

CMD ["uvicorn", "sentinel.server:app", "--host", "0.0.0.0", "--port", "8080"]
