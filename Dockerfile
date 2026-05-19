FROM python:3.11-slim

WORKDIR /app

# 1. Instal OS-level dependencies untuk OpenCV dan image processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 2. Create non-root user untuk security
RUN useradd -m -u 1000 appuser

# 3. Salin requirements.txt terlebih dahulu untuk memanfaatkan cache Docker
COPY requirements.txt .

# 4. Instal Python dependencies
# Menggunakan mirror yang stabil dan menambahkan timeout
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt

# 5. Salin seluruh kode aplikasi
COPY . .

# 6. Setup model directory dan copy u2net.onnx
RUN mkdir -p /home/appuser/.u2net && \
    if [ -f u2net.onnx ]; then cp u2net.onnx /home/appuser/.u2net/u2net.onnx; fi && \
    mkdir -p /app/uploads/processed /app/database && \
    chown -R appuser:appuser /app /home/appuser

# 7. Switch ke non-root user
USER appuser

# 8. Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
ENV HOME=/home/appuser

# 9. Ekspos port
EXPOSE 5100

# 10. Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5100/health', timeout=5)" || exit 1

# 11. Jalankan aplikasi dengan Gunicorn untuk production
CMD ["gunicorn", "--bind", "0.0.0.0:5100", "--workers", "2", "--threads", "2", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]