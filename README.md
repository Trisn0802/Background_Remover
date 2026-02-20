# Background Remover

A simple flask app to remove the background of an image with [Rembg](https://
github.com/danielgatis/rembg)

## Must do

```
change name :
1. database.exmaple to database
2. uploads.example to uploads
```

## Run it

```
pip install -r requirements.txt
python app.py
```

## Docker Compose

Buat file `docker-compose.yml` seperti berikut:

```yaml
services:
  happy_bank:
    build: .
    container_name: background_remover
    ports:
      - "5100:5100"
    volumes:
      - ./database:/app/database
      - ./uploads:/app/uploads
    restart: unless-stopped
```

Kalau mau lebih lengkap, tambahkan cara jalaninnya:


Jalankan:

```bash
docker compose up -d --build
docker compose ps
```

Catatan kecil: pastikan nama file image kamu `Dockerfile` (huruf **D** besar), bukan `dockerfile`.
