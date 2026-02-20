FROM python:3.11

WORKDIR /app

# 1. Salin requirements.txt terlebih dahulu untuk memanfaatkan cache Docker
COPY requirements.txt .

# 2. Instal dependensi (onnxruntime akan ikut terinstal)
RUN pip install --no-cache-dir -r requirements.txt

# 3. Salin seluruh kode aplikasi (termasuk u2net.onnx)
COPY . .

# download this https://github.com/danielgatis/rembg/releases/download/v0.0.0/u2net.onnx
# copy model to avoid unnecessary download

# 4. Buat folder yang diperlukan dan pindahkan model ke lokasi yang benar
RUN mkdir -p /root/.u2net && \
    if [ -f u2net.onnx ]; then cp u2net.onnx /root/.u2net/u2net.onnx; fi && \
    # Pastikan folder uploads/processed dan database sudah ada (opsional, karena nanti dibuat oleh kode)
    mkdir -p /app/uploads/processed /app/database

# 5. Ekspos port
EXPOSE 5100

# 6. Jalankan aplikasi
CMD ["python", "app.py"]