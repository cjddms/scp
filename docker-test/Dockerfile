FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx mitmproxy
COPY nac-proxy.py dashboard.html ./
COPY docker-test /app/docker-test
ENV PYTHONUNBUFFERED=1 NAC_DB_PATH=/data/nac.db TZ=Asia/Seoul
CMD ["python", "docker-test/run_api.py"]
