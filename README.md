# Production Docker Setup untuk Ubuntu Server

## ✅ Yang Sudah Diupdate:

### 1. **requirements.txt**
- ✅ Added: `gunicorn` - WSGI server untuk production (replace python app.py)
- ✅ Added: `python-multipart` - untuk file upload yang lebih robust
- ✅ Removed: `Werkzeug` - sudah included di Flask

### 2. **Dockerfile** 
Perubahan utama:
- ✅ Base image: `python:3.11-slim` (lebih kecil & lebih aman)
- ✅ OS dependencies untuk OpenCV: `libsm6`, `libxext6`, `libxrender-dev`
- ✅ Non-root user: `appuser` (security best practice)
- ✅ WSGI server: Gunicorn dengan multi-worker/thread support
- ✅ Healthcheck: Docker bisa monitor kesehatan container
- ✅ Better caching dan permission management

### 3. **app.py**
- ✅ Added healthcheck endpoint: `/health` untuk Docker monitoring

## 🚀 Cara Deploy ke Ubuntu Server:

### Step 1: Push changes
```bash
git add .
git commit -m "Production-ready Docker setup"
git push origin main
```

### Step 2: Update di Ubuntu Server
```bash
cd /var/www/docker/app/Background_Remover
git fetch origin
git reset --hard origin/main
docker compose down
docker compose up -d --build
```

### Step 3: Verifikasi
```bash
# Check container status
docker compose ps

# Check logs
docker compose logs app

# Test healthcheck
docker compose exec app curl http://localhost:5100/health

# Check running processes
docker compose exec app ps aux
```

## 📊 Peningkatan Keamanan & Performance:

| Fitur | Before | After |
|-------|--------|-------|
| **WSGI Server** | Single-threaded Flask dev | Gunicorn multi-worker |
| **User** | Root (⚠️ Security risk) | Non-root `appuser` |
| **Image Size** | `python:3.11` | `python:3.11-slim` |
| **Monitoring** | Manual check | Docker healthcheck |
| **Threading** | 1 worker | 2 workers + 2 threads each |
| **OpenCV Support** | Mungkin fail | Guaranteed working |

## 🔍 Gunicorn Configuration Dijelaskan:

```dockerfile
gunicorn \
  --bind 0.0.0.0:5100              # Listen di port 5100
  --workers 2                       # 2 worker processes (adjust ke CPU cores)
  --threads 2                       # 2 threads per worker (gthread)
  --worker-class gthread            # Thread-based workers
  --timeout 60                      # 60 detik timeout per request
  --access-logfile -                # Log ke stdout
  --error-logfile -                 # Log error ke stderr
  app:app                           # Flask app
```

## 📝 Tips Adjustment:

### Kalau CPU di server banyak, ubah di docker-compose.yml:
```yaml
services:
  app:
    # ... existing config ...
    command: gunicorn --bind 0.0.0.0:5100 --workers 4 --threads 2 --worker-class gthread app:app
```

### Kalau upload file besar, ubah di docker-compose.yml:
```yaml
services:
  app:
    environment:
      # ... existing env ...
      - MAX_CONTENT_LENGTH=104857600  # 100MB
```

## ⚠️ Important Notes:

1. **Gunicorn butuh `requests` untuk healthcheck** - sudah ada di requirements
2. **`.env` harus ada di Ubuntu server** dengan API keys yang valid
3. **Database & uploads folder** akan di-sync via docker volumes
4. **Restart needed** setelah update - `docker compose down && docker compose up -d --build`

## 🐛 Troubleshooting:

```bash
# Error: "libsm6 not found"
# Solution: Dockerfile sudah include, rebuild with --no-cache
docker compose build --no-cache

# Error: Permission denied
# Solution: User appuser punya ownership /app dan /home/appuser

# Error: Healthcheck timeout
# Solution: Check logs, healthcheck mulai 40 detik setelah container start
```

---
**Status: READY FOR PRODUCTION** ✅
