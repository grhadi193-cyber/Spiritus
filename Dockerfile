FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PORT=8080

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
COPY requirements-dpi.txt requirements-dpi.txt
COPY requirements-firewall.txt requirements-firewall.txt

RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    if [ -f requirements-dpi.txt ]; then pip install -r requirements-dpi.txt; fi && \
    if [ -f requirements-firewall.txt ]; then pip install -r requirements-firewall.txt; fi

COPY . .

EXPOSE 8080

CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"
