FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY guardian_engine ./guardian_engine
COPY fixtures ./fixtures

EXPOSE 8000

CMD ["uvicorn", "guardian_engine.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
