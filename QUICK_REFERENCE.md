# 🚀 Quick Command Reference

## PERTAMA KALI DI SERVER BARU

```bash
# 1. Create directory
sudo mkdir -p /var/www/docker/app
cd /var/www/docker/app

# 2. Download script
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/Background_Remover/main/update_and_run.sh
chmod +x update_and_run.sh

# 3. Edit script - ubah REPO_URL
nano update_and_run.sh

# 4. Run script (ini akan git clone otomatis!)
./update_and_run.sh

# 5. Edit .env dengan API keys
nano /var/www/docker/app/Background_Remover/.env

# 6. Restart container
cd /var/www/docker/app/Background_Remover
docker compose restart
```

## UPDATE BERIKUTNYA (SETIAP KALI ADA PERUBAHAN)

```bash
cd /var/www/docker/app/Background_Remover
./update_and_run.sh
```

Itu saja! Script handle semuanya ✅

---

## UTILITY COMMANDS

```bash
# Check status
docker compose ps

# View logs
docker compose logs -f app

# Test healthcheck
curl http://localhost:5100/health

# Enter container shell
docker compose exec app bash

# Stop container
docker compose down

# Restart container
docker compose restart

# View env variables
docker compose exec app env

# Manual git pull (tanpa rebuild)
cd /var/www/docker/app/Background_Remover && git pull origin main

# Force rebuild Docker image
docker compose build --no-cache && docker compose up -d
```

---

## SCRIPT FLOW DIAGRAM

```
START
  │
  ├─→ Check if git repo exists
  │   ├─ YES: Skip clone
  │   └─ NO: Clone repository (first time!)
  │
  ├─→ Git fetch & reset (update code)
  │
  ├─→ Verify Docker & Docker Compose
  │
  ├─→ Check .env file
  │   └─ If not exist: Create from .env.example
  │
  ├─→ Docker compose down (stop old container)
  │
  ├─→ Docker compose up --build (start new)
  │
  ├─→ Wait for container ready (healthcheck)
  │
  ├─→ Display status & logs
  │
  └─→ END ✅
```

---

## KEAMANAN TIPS

- ✅ **Jangan commit .env ke GitHub** (sudah di .gitignore)
- ✅ **Ubah SECRET_KEY** di .env production
- ✅ **Setup firewall** - hanya port 5100 yang diperlukan
- ✅ **Backup database** sebelum update besar
- ✅ **Gunakan SSH** untuk git clone (lebih aman dari HTTPS)

---

## MONITORING

### Cek container health
```bash
docker compose ps
# Look for STATUS column - harus "Up"
```

### Tail logs real-time
```bash
docker compose logs -f app
```

### Check resource usage
```bash
docker stats background_remover
```

---

**Documentation: COMPLETE** ✅
