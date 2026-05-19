# Troubleshooting Update Script

## Masalah: Script Error / Output tidak jelas di tmux

### Penyebab Umum:

1. **REPO_URL tidak benar** - perlu edit manual
2. **Permission issues** - folder/file tidak writable
3. **Docker not running** - Docker daemon tidak start
4. **.env file hilang** - API keys tidak tersedia
5. **Network issues** - tidak bisa akses GitHub/Docker registry

---

## 🔍 Step 1: Jalankan Debug Script

```bash
# Download debug script jika belum ada
curl -O https://raw.githubusercontent.com/Trisn0802/Background_Remover/main/debug.sh
chmod +x debug.sh

# Jalankan
./debug.sh
```

Output akan menunjukkan status semua komponen.

---

## 🔧 Step 2: Script SUDAH Dikonfigurasi ✅

GitHub URL sudah di-set ke:
```bash
REPO_URL="https://github.com/Trisn0802/Background_Remover.git"
```

Tidak perlu edit! Langsung ke Step 3.

---

## 📝 Step 3: Jalankan Script Dengan Logging

### Option A: Direct execution (lihat output langsung)

```bash
cd /var/www/docker/app/Background_Remover
bash -x ./update_and_run.sh
# -x flag: print each command sebelum execute
```

### Option B: Dengan tmux (recommended)

```bash
# Create tmux session
tmux new-session -s update

# Run script inside tmux
tmux send-keys -t update 'cd /var/www/docker/app/Background_Remover && ./update_and_run.sh' Enter

# Attach ke session
tmux attach -t update

# Untuk detach (exit tmux): Ctrl+B → D
```

### Option C: Background dengan log file

```bash
cd /var/www/docker/app/Background_Remover
nohup ./update_and_run.sh > update_output.log 2>&1 &

# Monitor log in real-time
tail -f update_output.log

# Monitor both log files
tail -f /var/log/bg-remover-update.log
tail -f update_output.log
```

---

## 🔍 Step 4: Check Log Files

Script sekarang membuat log file otomatis:

```bash
# Primary log (maintained script)
tail -f /var/log/bg-remover-update.log

# Or jika write permission denied:
tail -f /var/www/docker/app/Background_Remover/update.log

# Lihat semua update logs
ls -lh /var/log/bg-remover-*.log
ls -lh /var/www/docker/app/Background_Remover/*.log
```

---

## 🚨 Solusi untuk Error Spesifik

### Error: "Permission denied"

```bash
# Check permissions
ls -ld /var/www/docker/app/Background_Remover

# Fix: Change owner
sudo chown -R $USER:$USER /var/www/docker/app/Background_Remover
chmod -R 755 /var/www/docker/app/Background_Remover

# Or untuk log file
sudo touch /var/log/bg-remover-update.log
sudo chmod 666 /var/log/bg-remover-update.log
```

### Error: "Git clone failed"

```bash
# Check git credentials
git config --global --list

# Test SSH connection (jika pakai SSH)
ssh -T git@github.com

# Fix: Setup SSH key jika belum
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub  # Copy ke GitHub Settings > SSH Keys

# Or test HTTPS
git clone https://github.com/Trisn0802/Background_Remover.git /tmp/test
```

### Error: "Docker not found"

```bash
# Check if Docker running
docker ps

# If error "Cannot connect to daemon":
sudo systemctl start docker

# Check status
sudo systemctl status docker

# Enable auto-start
sudo systemctl enable docker
```

### Error: ".env file not found"

```bash
# Check if file exists
ls -la /var/www/docker/app/Background_Remover/.env*

# If .env.example exists, copy manually
cp /var/www/docker/app/Background_Remover/.env.example \
   /var/www/docker/app/Background_Remover/.env

# Edit & set API keys
nano /var/www/docker/app/Background_Remover/.env
```

### Error: "Container won't start"

```bash
# Check container status
docker compose ps -a

# View container logs
docker compose logs --tail=100 app

# Try rebuilding
docker compose down
docker compose up -d --build

# If still fails, check image
docker images | grep background_remover
```

---

## 📊 Manual Workflow (Jika Script Fail)

Jika script terus error, jalankan step-by-step:

```bash
# 1. Navigate
cd /var/www/docker/app/Background_Remover

# 2. Git sync
git fetch origin
git reset --hard origin/main

# 3. Check Docker
docker version
docker compose version

# 4. Check .env
cat .env

# 5. Stop containers
docker compose down

# 6. Build & start
docker compose up -d --build

# 7. Wait & check
sleep 30
docker compose ps
docker compose logs app
```

---

## 💡 Tips for Debugging

### 1. Increase verbosity
```bash
# Git
export GIT_TRACE=1
git fetch origin

# Docker
docker -D compose up -d --build
```

### 2. Check environment
```bash
# Verify all variables are set
env | grep -E "(ROBOFLOW|SECRET|FLASK)"

# Check PATH
echo $PATH
```

### 3. Check network
```bash
# Test GitHub connection
curl -I https://github.com

# Test Docker registry
curl -I https://registry.hub.docker.com
```

### 4. View detailed logs
```bash
# Docker engine logs
journalctl -u docker.service -n 50

# System logs
dmesg | tail -20
```

---

## ✅ Verification Checklist

Setelah berhasil:

- [ ] Container running: `docker compose ps` → Status: "Up"
- [ ] Healthcheck pass: `docker compose exec app curl http://localhost:5100/health`
- [ ] App accessible: `curl http://localhost:5100/`
- [ ] Logs clean: `docker compose logs app` → no ERROR
- [ ] .env loaded: `docker compose exec app env | grep ROBOFLOW`

---

## 📞 Quick Reference

| Command | Purpose |
|---------|---------|
| `./debug.sh` | Full system diagnostics |
| `tail -f /var/log/bg-remover-update.log` | Monitor script logs |
| `docker compose logs -f app` | Monitor container logs |
| `docker compose ps` | Check container status |
| `docker compose restart` | Restart without rebuild |
| `nano /var/www/docker/app/Background_Remover/.env` | Edit config |

---

**Need more help?** Check the logs first! 90% of issues are in the logs. 📋
