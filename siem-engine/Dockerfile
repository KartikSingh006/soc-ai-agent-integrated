FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared/ /app/shared/
COPY alembic.ini /app/alembic.ini
COPY migrations/ /app/migrations/
COPY siem-engine/src/ /app/src/

ENV PYTHONPATH=/app

CMD ["python", "/app/src/main.py"]
