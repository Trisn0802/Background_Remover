# Background Remover

A simple flask app to remove the background of an image with [Rembg](https://github.com/danielgatis/rembg)

## Must do

```md
change name :
1. database.exmaple to database
2. uploads.example to uploads
```

## Run it

```md
pip install -r requirements.txt
python app.py
```

## Docker Compose

create file `docker-compose.yml` as follows:

```yaml
services:
  app:
    build: .
    container_name: background_remover
    ports:
      - "5100:5100"
    volumes:
      - .:/app          # mount seluruh kode dari host (overwrite hasil build)
      - /app/node_modules  # kecualikan node_modules jika ada
      - uploads_data:/app/uploads/processed
      - db_data:/app/database
    restart: unless-stopped
    
volumes:
  uploads_data:
  db_data:
```

After that run this command:

```bash
docker compose up -d --build
docker compose ps
```

Small note: make sure your image file name is `Dockerfile` (capital letter **D**), not `dockerfile`.
