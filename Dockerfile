FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

COPY . .

ENV FLASK_APP=server:app

ENV PORT=8080

CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT:-8080} server:app"]
