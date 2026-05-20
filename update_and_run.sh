#!/bin/bash

# Color codes untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ====================================================================
# LOGGING SETUP
# ====================================================================
LOG_FILE="/var/log/bg-remover-update.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to write to /var/log, fallback to script directory
if [ -w /var/log ]; then
    LOG_FILE="/var/log/bg-remover-update.log"
else
    LOG_FILE="$SCRIPT_DIR/update.log"
fi

# Function untuk logging
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    echo -e "${BLUE}[$level]${NC} $message"
}

log_error() {
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [ERROR] $message" >> "$LOG_FILE"
    echo -e "${RED}[ERROR]${NC} $message"
}

log_success() {
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [SUCCESS] $message" >> "$LOG_FILE"
    echo -e "${GREEN}[SUCCESS]${NC} $message"
}

log_warn() {
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [WARNING] $message" >> "$LOG_FILE"
    echo -e "${YELLOW}[WARNING]${NC} $message"
}

# Log start
log "INFO" "========================================="
log "INFO" "Script dimulai - $(date)"
log "INFO" "User: $(whoami)"
log "INFO" "PWD: $(pwd)"
log "INFO" "========================================="

# Konfigurasi
REPO_DIR="/var/www/docker/app/Background_Remover"
REPO_URL="https://github.com/Trisn0802/Background_Remover.git"
BRANCH="main"
PARENT_DIR="/var/www/docker/app"

log "INFO" "Konfigurasi:"
log "INFO" "  REPO_DIR: $REPO_DIR"
log "INFO" "  REPO_URL: $REPO_URL"
log "INFO" "  BRANCH: $BRANCH"
log "INFO" "  LOG_FILE: $LOG_FILE"

# ====================================================================
# STEP 1: CEK APAKAH REPO SUDAH ADA
# ====================================================================
log "INFO" "STEP 1: Checking Git repository status..."

if [ ! -d "$REPO_DIR/.git" ]; then
    log_warn "Git repository belum ada. Akan melakukan clone..."
    
    # Cek apakah parent directory ada
    if [ ! -d "$PARENT_DIR" ]; then
        log "INFO" "Creating parent directory: $PARENT_DIR"
        mkdir -p "$PARENT_DIR" 2>> "$LOG_FILE" || {
            log_error "Gagal membuat direktori $PARENT_DIR"
            exit 1
        }
    fi
    
    # Jika folder sudah ada tapi tidak git repo, backup terlebih dahulu
    if [ -d "$REPO_DIR" ]; then
        log_warn "Folder $REPO_DIR sudah ada tapi bukan git repo"
        BACKUP_DIR="${REPO_DIR}_backup_$(date +%s)"
        log "INFO" "Backup ke: $BACKUP_DIR"
        mv "$REPO_DIR" "$BACKUP_DIR" 2>> "$LOG_FILE" || {
            log_error "Gagal backup folder"
            exit 1
        }
    fi
    
    # Clone repository
    log "INFO" "Cloning repository dari: $REPO_URL"
    git clone -b "$BRANCH" "$REPO_URL" "$REPO_DIR" 2>> "$LOG_FILE" || {
        log_error "Git clone gagal"
        log_error "Pastikan:"
        log_error "  1. REPO_URL sudah benar (edit script: REPO_URL=...)"
        log_error "  2. GitHub repository ada & accessible"
        log_error "  3. SSH key tersetup (jika menggunakan SSH)"
        exit 1
    }
    log_success "Git clone berhasil"
else
    log_success "Git repository sudah ada"
fi

# ====================================================================
# STEP 2: MASUK KE DIREKTORI DAN SINKRONISASI
# ====================================================================
log "INFO" "STEP 2: Sinkronisasi dengan GitHub..."

cd "$REPO_DIR" 2>> "$LOG_FILE" || {
    log_error "Gagal masuk ke direktori: $REPO_DIR"
    exit 1
}

log "INFO" "Current directory: $(pwd)"

# Check directory permissions
log "INFO" "Checking directory permissions..."
if [ ! -r "$REPO_DIR" ]; then
    log_error "Tidak bisa read direktori: $REPO_DIR"
    log_error "User: $(whoami), uid: $(id -u)"
    log_error "Directory owner: $(ls -ld $REPO_DIR | awk '{print $3, $4}')"
    log_error "Solution: sudo chown -R $(whoami):$(id -gn) $REPO_DIR"
    exit 1
fi

if [ ! -w "$REPO_DIR" ]; then
    log_warn "Tidak bisa write ke direktori (non-critical untuk git fetch)"
fi

# Check git config
log "INFO" "Checking git remote..."
git remote -v 2>> "$LOG_FILE" | while read line; do
    log "INFO" "  Remote: $line"
done

# Fetch latest changes dengan error capture
log "INFO" "Running: git fetch origin"
FETCH_OUTPUT=$(git fetch origin 2>&1)
FETCH_EXIT=$?

if [ $FETCH_EXIT -ne 0 ]; then
    log_error "Git fetch gagal (exit code: $FETCH_EXIT)"
    log_error "Error output:"
    echo "$FETCH_OUTPUT" | while read line; do
        log_error "  $line"
    done
    log_error "Troubleshooting:"
    log_error "  1. Check git remote: git remote -v"
    log_error "  2. Check permissions: ls -la .git"
    log_error "  3. Test SSH (if using SSH): ssh -T git@github.com"
    log_error "  4. Test HTTPS: curl -I https://github.com/Trisn0802/Background_Remover.git"
    exit 1
fi
log_success "Git fetch berhasil"

# Reset ke branch utama dengan error capture
log "INFO" "Running: git reset --hard origin/$BRANCH"
RESET_OUTPUT=$(git reset --hard origin/"$BRANCH" 2>&1)
RESET_EXIT=$?

if [ $RESET_EXIT -ne 0 ]; then
    log_error "Git reset gagal (exit code: $RESET_EXIT)"
    log_error "Error output:"
    echo "$RESET_OUTPUT" | while read line; do
        log_error "  $line"
    done
    exit 1
fi
log_success "Git reset ke origin/$BRANCH berhasil"

# Clean untracked files (opsional)
log "INFO" "Running: git clean -fd"
if ! git clean -fd 2>> "$LOG_FILE"; then
    log_warn "Git clean failed (non-critical)"
fi

# ====================================================================
# STEP 3: VERIFIKASI DOCKER & DOCKER COMPOSE
# ====================================================================
log "INFO" "STEP 3: Verifying Docker installation..."

if ! command -v docker &> /dev/null; then
    log_error "Docker tidak terinstall"
    log "INFO" "Install Docker: https://docs.docker.com/install/"
    exit 1
fi
log_success "Docker terinstall: $(docker --version)"

if ! command -v docker compose &> /dev/null; then
    log_error "Docker Compose tidak terinstall"
    log "INFO" "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
log_success "Docker Compose terinstall: $(docker compose version)"

# ====================================================================
# STEP 4: SETUP .ENV FILE JIKA BELUM ADA
# ====================================================================
log "INFO" "STEP 4: Checking .env file..."

if [ ! -f "$REPO_DIR/.env" ]; then
    log_warn "File .env tidak ditemukan"
    if [ -f "$REPO_DIR/.env.example" ]; then
        log "INFO" "Membuat .env dari .env.example"
        cp "$REPO_DIR/.env.example" "$REPO_DIR/.env" 2>> "$LOG_FILE" || {
            log_error "Gagal copy .env.example"
            exit 1
        }
        log_warn "⚠️  PENTING: EDIT .env dan set API keys:"
        log_warn "   - ROBOFLOW_API_KEY"
        log_warn "   - ROBOFLOW_WORKSPACE"
        log_warn "   - SECRET_KEY"
        log_warn "   Command: nano $REPO_DIR/.env"
        sleep 3
    else
        log_error ".env.example tidak ditemukan"
        exit 1
    fi
else
    log_success ".env file sudah ada"
fi

# ====================================================================
# STEP 5: STOP DAN REMOVE CONTAINER LAMA
# ====================================================================
log "INFO" "STEP 5: Stopping old containers..."

if ! docker compose down 2>> "$LOG_FILE"; then
    log_error "Docker compose down gagal"
    exit 1
fi
log_success "Docker compose down berhasil"

# ---------------------------------------------------------
# TAMBAHKAN BARIS INI DI SKRIP UPDATE SEBELUM DOCKER COMPOSE UP
# ---------------------------------------------------------
echo "[INFO] Menyelaraskan izin akses folder untuk Non-Root User..."
mkdir -p database uploads/processed
sudo chown -R 1000:1000 database uploads
# ---------------------------------------------------------

# ====================================================================
# STEP 6: BUILD DAN JALANKAN CONTAINER BARU
# ====================================================================
log "INFO" "STEP 6: Building and running Docker container..."

if ! docker compose up -d --build 2>> "$LOG_FILE"; then
    log_error "Docker compose up gagal"
    log "INFO" "Debug: Lihat error di atas atau di log file: $LOG_FILE"
    docker compose logs --tail=50 app 2>> "$LOG_FILE" || true
    exit 1
fi
log_success "Docker compose up berhasil"

# ====================================================================
# STEP 7: WAIT UNTUK CONTAINER SIAP
# ====================================================================
log "INFO" "STEP 7: Waiting for container to be ready (max 60 detik)..."
WAIT_TIME=0
MAX_WAIT=60

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    if docker compose exec -T app curl -f http://localhost:5100/health &> /dev/null; then
        log_success "Container siap!"
        break
    fi
    echo -n "." >> "$LOG_FILE"
    sleep 1
    WAIT_TIME=$((WAIT_TIME + 1))
done

if [ $WAIT_TIME -eq $MAX_WAIT ]; then
    log_warn "Timeout menunggu container siap"
    log_warn "Container mungkin masih starting... cek logs dengan: docker compose logs -f app"
fi

echo ""

# ====================================================================
# STEP 8: TAMPILKAN STATUS & LOGS
# ====================================================================
log_success "Proses Selesai!"
log "INFO" "========================================="

log "INFO" "Status Container:"
docker compose ps 2>> "$LOG_FILE" | tee -a "$LOG_FILE"

log "INFO" "Recent Logs (last 30 lines):"
docker compose logs --tail=30 app 2>> "$LOG_FILE" | tee -a "$LOG_FILE"

log "INFO" "========================================="
log "INFO" "INFORMASI PENTING:"
log "INFO" "  Container Name: background_remover"
log "INFO" "  Akses aplikasi: http://localhost:5100"
log "INFO" "  Lihat logs: docker compose logs -f app"
log "INFO" "  Stop container: docker compose down"
log "INFO" "  Log file: $LOG_FILE"
log "INFO" "========================================="
log "INFO" "Script selesai - $(date)"

echo ""
echo -e "${GREEN}✓ Update selesai!${NC}"
echo -e "${BLUE}Log file: $LOG_FILE${NC}"