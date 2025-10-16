FROM python:3.11-slim

WORKDIR /app

# Copier app.py
COPY app.py /app/

# Installer Flask
RUN pip install --no-cache-dir flask

# Créer le dossier uploads et /var/ctf (utilisé par ton app)
RUN mkdir -p /app/uploads /var/ctf

EXPOSE 5000

CMD ["python", "app.py"]
