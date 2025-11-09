FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV PYTHONPATH ${PYTHONPATH}:'/app'
ENV FLASK_RUN_RELOAD=true

ENTRYPOINT ["flask", "--app", "app", "run", "-h", "0.0.0.0", "-p", "8080"]

