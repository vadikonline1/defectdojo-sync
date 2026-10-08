FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/

RUN groupadd --gid 10001 syncuser \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin syncuser \
    && mkdir -p /data/openvas-reports /data/wazuh-reports /data/state \
    && chown -R 10001:10001 /app /data \
    && chmod 750 /data /data/openvas-reports /data/wazuh-reports /data/state

USER 10001:10001

CMD ["python", "-m", "sync"]
