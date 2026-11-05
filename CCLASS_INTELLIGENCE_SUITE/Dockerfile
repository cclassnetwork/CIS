# CCLASS Intelligence Suite - container image (runs as an unprivileged user, data in /data)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CCLASS_HOME=/data \
    CCLASS_HOST=0.0.0.0 \
    CCLASS_PORT=8000

WORKDIR /app
COPY requirements.txt .
# pytest/httpx are only needed for the test-suite; they are small, so one requirements file is kept.
RUN pip install -r requirements.txt

COPY . .
RUN useradd --system --uid 10001 --home-dir /app cclass \
    && mkdir -p /data && chown -R cclass:cclass /data
USER cclass
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

# Only the reverse proxy in docker-compose.yml can reach this port; it is never published to the host.
CMD ["python", "cclass.py", "--dashboard", "--no-demo-prompt"]
