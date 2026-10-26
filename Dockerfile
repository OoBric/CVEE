FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py tracking.py m365_sync.py cloud_app.py ./
COPY static ./static
ENV PYTHONUNBUFFERED=1
ENV VULNSCOPE_DB_PATH=/data/cve_tracking.sqlite3
EXPOSE 8000
CMD ["sh", "-c", "uvicorn cloud_app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
