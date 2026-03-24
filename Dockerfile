FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpcap-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.lock

COPY . .
RUN python -m pip install -e .

CMD ["python", "-m", "tls_dataset", "info"]
