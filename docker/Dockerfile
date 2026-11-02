FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    lynis \
    ufw \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

COPY . .
EXPOSE 8000 8501

CMD ["bash", "run_sara.sh"]
