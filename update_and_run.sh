#!/bin/bash

# Color codes untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Konfigurasi
REPO_DIR="/var/www/docker/app/Background_Remover"
REPO_URL="https://github.com/YOUR_USERNAME/Background_Remover.git"  # ⚠️ GANTI URL INI
BRANCH="main"
PARENT_DIR="/var/www/docker/app"

# ====================================================================
# STEP 1: CEK APAKAH REPO SUDAH ADA
# ====================================================================
echo -e "${BLUE}[INFO]${NC} Checking Git repository status..."

if [ ! -d "$REPO_DIR/.git" ]; then
    echo -e "${YELLOW}[WARNING]${NC} Git repository belum ada. Akan melakukan clone..."
    
    # Cek apakah parent directory ada
    if [ ! -d "$PARENT_DIR" ]; then
        echo -e "${YELLOW}[INFO]${NC} Creating parent directory: $PARENT_DIR"
        mkdir -p "$PARENT_DIR" || {
            echo -e "${RED}✗ Gagal membuat direktori $PARENT_DIR${NC}"
            exit 1
        }
    fi
    
    # Jika folder sudah ada tapi tidak git repo, backup terlebih dahulu
    if [ -d "$REPO_DIR" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Folder $REPO_DIR sudah ada tapi bukan git repo"
        BACKUP_DIR="${REPO_DIR}_backup_$(date +%s)"
        echo -e "${YELLOW}[INFO]${NC} Backup ke: $BACKUP_DIR"
        mv "$REPO_DIR" "$BACKUP_DIR" || {
            echo -e "${RED}✗ Gagal backup folder${NC}"
            exit 1
        }
    fi
    
    # Clone repository
    echo -e "${YELLOW}[INFO]${NC} Cloning repository dari: $REPO_URL"
    git clone -b "$BRANCH" "$REPO_URL" "$REPO_DIR" || {
        echo -e "${RED}✗ Git clone gagal${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Git clone berhasil${NC}"
else
    echo -e "${GREEN}✓ Git repository sudah ada${NC}"
fi

# ====================================================================
# STEP 2: MASUK KE DIREKTORI DAN SINKRONISASI
# ====================================================================
cd "$REPO_DIR" || exit 1

echo -e "${YELLOW}--- Memastikan folder sinkron dengan GitHub ---${NC}"

# Fetch latest changes
if git fetch origin; then
    echo -e "${GREEN}✓ Git fetch berhasil${NC}"
else
    echo -e "${RED}✗ Git fetch gagal${NC}"
    exit 1
fi

# Reset ke branch utama
if git reset --hard origin/"$BRANCH"; then
    echo -e "${GREEN}✓ Git reset ke origin/$BRANCH berhasil${NC}"
else
    echo -e "${RED}✗ Git reset gagal${NC}"
    exit 1
fi

# Clean untracked files (opsional)
git clean -fd || {
    echo -e "${RED}✗ Git clean gagal${NC}"
}

# ====================================================================
# STEP 3: VERIFIKASI DOCKER & DOCKER COMPOSE
# ====================================================================
echo -e "${BLUE}[INFO]${NC} Verifying Docker installation..."

if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker tidak terinstall${NC}"
    echo -e "${YELLOW}[INFO]${NC} Install Docker: https://docs.docker.com/install/"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose tidak terinstall${NC}"
    echo -e "${YELLOW}[INFO]${NC} Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✓ Docker & Docker Compose terinstall${NC}"

# ====================================================================
# STEP 4: SETUP .ENV FILE JIKA BELUM ADA
# ====================================================================
if [ ! -f "$REPO_DIR/.env" ]; then
    echo -e "${YELLOW}[WARNING]${NC} File .env tidak ditemukan"
    if [ -f "$REPO_DIR/.env.example" ]; then
        echo -e "${YELLOW}[INFO]${NC} Membuat .env dari .env.example"
        cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
        echo -e "${YELLOW}[WARNING]${NC} ⚠️  EDIT .env dan set API keys:"
        echo -e "${YELLOW}   - ROBOFLOW_API_KEY${NC}"
        echo -e "${YELLOW}   - ROBOFLOW_WORKSPACE${NC}"
        echo -e "${YELLOW}   - SECRET_KEY${NC}"
        sleep 3
    else
        echo -e "${RED}✗ .env.example tidak ditemukan${NC}"
        exit 1
    fi
fi

# ====================================================================
# STEP 5: STOP DAN REMOVE CONTAINER LAMA
# ====================================================================
echo -e "${YELLOW}--- Menghentikan dan menghapus container lama ---${NC}"

if docker compose down; then
    echo -e "${GREEN}✓ Docker compose down berhasil${NC}"
else
    echo -e "${RED}✗ Docker compose down gagal${NC}"
    exit 1
fi

# ====================================================================
# STEP 6: BUILD DAN JALANKAN CONTAINER BARU
# ====================================================================
echo -e "${YELLOW}--- Membangun dan menjalankan container Docker ---${NC}"

if docker compose up -d --build; then
    echo -e "${GREEN}✓ Docker compose up berhasil${NC}"
else
    echo -e "${RED}✗ Docker compose up gagal${NC}"
    echo -e "${YELLOW}[INFO]${NC} Debug: lihat error di atas"
    exit 1
fi

# ====================================================================
# STEP 7: WAIT UNTUK CONTAINER SIAP
# ====================================================================
echo -e "${YELLOW}[INFO]${NC} Menunggu container siap (max 60 detik)..."
WAIT_TIME=0
MAX_WAIT=60

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    if docker compose exec -T app curl -f http://localhost:5100/health &> /dev/null; then
        echo -e "${GREEN}✓ Container siap!${NC}"
        break
    fi
    echo -n "."
    sleep 1
    WAIT_TIME=$((WAIT_TIME + 1))
done

if [ $WAIT_TIME -eq $MAX_WAIT ]; then
    echo -e "${YELLOW}[WARNING]${NC} Timeout menunggu container siap"
fi

echo ""

# ====================================================================
# STEP 8: TAMPILKAN STATUS & LOGS
# ====================================================================
echo -e "${GREEN}--- Proses Selesai! ---${NC}"

echo -e "${YELLOW}--- Status Container ---${NC}"
docker compose ps

echo -e "${YELLOW}--- Recent Logs (last 30 lines) ---${NC}"
docker compose logs --tail=30 app

echo -e "${BLUE}--- INFORMASI PENTING ---${NC}"
echo -e "${GREEN}✓ Container Name:${NC} background_remover"
echo -e "${GREEN}✓ Container Status:${NC} $(docker compose ps --format 'table {{.Status}}' app)"
echo -e "${GREEN}✓ Akses aplikasi:${NC} http://localhost:5100"
echo -e "${GREEN}✓ Lihat logs:${NC} docker compose logs -f app"
echo -e "${GREEN}✓ Stop container:${NC} docker compose down"
echo ""
