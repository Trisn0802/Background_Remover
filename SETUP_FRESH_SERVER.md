# Setup Awal untuk Ubuntu Server FRESH (Belum Git Clone)

## 📋 Prerequisites

Pastikan server sudah punya:
- ✅ Docker installed
- ✅ Docker Compose installed
- ✅ Git installed
- ✅ SSH key tersetup (untuk GitHub akses)

### Install jika belum ada:

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add current user ke docker group (so no sudo needed)
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose (jika belum included)
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
sudo apt-get install -y git

# Verifikasi
docker --version
docker compose version
git --version
```

## 🚀 Setup Untuk Server BARU (First Time)

### Step 1: Prepare Directory
```bash
# Create parent directory
sudo mkdir -p /var/www/docker/app
cd /var/www/docker/app

# Set permissions (opsional, jika ada ownership issues)
sudo chown $USER:$USER /var/www/docker/app
chmod 755 /var/www/docker/app
```

### Step 2: Download Script
```bash
# Download update_and_run.sh
curl -O https://raw.githubusercontent.com/Trisn0802/Background_Remover/main/update_and_run.sh

# Atau jika sudah ada:
wget https://raw.githubusercontent.com/Trisn0802/Background_Remover/main/update_and_run.sh

# Make executable
chmod +x update_and_run.sh
```

### Step 3: Script SUDAH Dikonfigurasi ✅

GitHub URL sudah otomatis di-set di script:
```bash
REPO_URL="https://github.com/Trisn0802/Background_Remover.git"
```

Tidak perlu edit lagi! Langsung jalankan saja. 🎉

### Step 4: Jalankan Script
```bash
# Run script
./update_and_run.sh
```

**Yang akan terjadi:**
1. ✅ Deteksi bahwa repo belum ada
2. ✅ Clone repository pertama kali
3. ✅ Verifikasi Docker & Docker Compose
4. ✅ Setup `.env` dari `.env.example` (if exists)
5. ✅ Build & run Docker container
6. ✅ Tunggu container siap
7. ✅ Tampilkan status & logs

### Step 5: Setup Environment Variables
```bash
# Edit .env file
nano /var/www/docker/app/Background_Remover/.env
```

Isi dengan:
```env
SECRET_KEY=your-strong-secret-key-here-change-this
ROBOFLOW_API_KEY=your_actual_api_key
ROBOFLOW_WORKSPACE=your_workspace
ROBOFLOW_WORKFLOW_ID=your_workflow_id
ROBOFLOW_MODEL_ID=your_model_id
FLASK_ENV=production
```

Simpan: `Ctrl+X → Y → Enter`

### Step 6: Restart Container
```bash
cd /var/www/docker/app/Background_Remover
docker compose down
docker compose up -d --build
```

### Step 7: Verifikasi
```bash
# Check status
docker compose ps

# Check logs
docker compose logs -f app

# Test healthcheck
curl http://localhost:5100/health

# Test aplikasi
curl http://localhost:5100/
```

---

## 🔄 Update Berikutnya (Untuk Kali Kedua & Seterusnya)

Cukup jalankan:
```bash
cd /var/www/docker/app/Background_Remover
./update_and_run.sh
```

Script akan:
- ✅ Deteksi repo sudah ada
- ✅ Pull latest changes
- ✅ Rebuild container dengan kode terbaru
- ✅ Auto-restart

---

## 🐛 Troubleshooting

### Error: "git clone permission denied"
**Solusi:** Setup SSH key
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub  # Copy & paste ke GitHub Settings > SSH Keys
```

### Error: "Docker daemon is not running"
**Solusi:**
```bash
# Check docker daemon
sudo systemctl status docker

# Start docker
sudo systemctl start docker

# Auto-start on boot
sudo systemctl enable docker
```

### Error: "Permission denied: /var/www/docker/app/Background_Remover"
**Solusi:**
```bash
# Fix permissions
sudo chown -R $USER:$USER /var/www/docker/app
chmod -R 755 /var/www/docker/app
```

### Error: "Container failed to start"
**Solusi:** Check logs detail
```bash
cd /var/www/docker/app/Background_Remover
docker compose logs --tail=100 app
```

### Error: ".env not found"
**Solusi:** Create manually
```bash
cd /var/www/docker/app/Background_Remover
cp .env.example .env
nano .env  # Edit dengan API keys
docker compose restart
```

---

## 📝 Setup untuk Cron Job (Auto-Update)

Jika ingin auto-update setiap jam:

```bash
# Edit crontab
crontab -e

# Tambahkan (setiap jam 3 pagi):
0 3 * * * cd /var/www/docker/app/Background_Remover && ./update_and_run.sh >> /var/log/bg-remover-update.log 2>&1
```

---

## ✅ Checklist Sebelum Deploy

- [ ] Server punya Docker & Docker Compose
- [ ] GitHub repository access sudah setup (SSH atau HTTPS)
- [ ] `.env` file sudah di-edit dengan API keys
- [ ] Port 5100 tidak terpakai
- [ ] Disk space cukup (minimal 2GB untuk images)
- [ ] Internet connection stable

---

**Status: READY FOR FRESH DEPLOYMENT** ✅
