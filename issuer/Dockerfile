FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_THREAD_LIMIT=1
WORKDIR /srv
# OCR des cartes (module d'enrôlement) : Tesseract + langue française ; le modèle MRZ est fourni dans app/ocr_data
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-fra \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# Certificat d'autorité optionnel (proxy d'entreprise qui inspecte TLS), fourni comme secret de build :
# il n'est jamais copié dans l'image.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r -u 10001 issuer && chown -R issuer /srv
USER issuer
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=10 CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
