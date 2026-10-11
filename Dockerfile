FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Default: dashboard + API. docker-compose overrides this per service
# (siem-agent runs `python main.py`).
CMD ["sh", "-c", "python -c 'from database import init_db; init_db()' && uvicorn api:app --host 0.0.0.0 --port 8000"]
