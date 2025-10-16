FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir flask

EXPOSE 5000

# Initialize DB at container start, then run app
CMD ["python", "app.py"]
