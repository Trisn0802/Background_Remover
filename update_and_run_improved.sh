#!/bin/bash

# Color codes untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Masuk ke direktori
cd /var/www/docker/app/Background_Remover || exit 1

echo -e "${YELLOW}--- Memastikan folder sinkron dengan GitHub ---${NC}"
# Menghapus perubahan lokal yang tidak perlu dan menarik versi terbaru
if git fetch origin; then
    echo -e "${GREEN}✓ Git fetch berhasil${NC}"
else
    echo -e "${RED}✗ Git fetch gagal${NC}"
    exit 1
fi

if git reset --hard origin/main; then
    echo -e "${GREEN}✓ Git reset berhasil${NC}"
else
    echo -e "${RED}✗ Git reset gagal${NC}"
    exit 1
fi

echo -e "${YELLOW}--- Mengupdate container Docker ---${NC}"

# Pastikan docker compose down berjalan sukses
if docker compose down; then
    echo -e "${GREEN}✓ Docker compose down berhasil${NC}"
else
    echo -e "${RED}✗ Docker compose down gagal${NC}"
    exit 1
fi

# Build dan jalankan container
if docker compose up -d --build; then
    echo -e "${GREEN}✓ Docker compose up berhasil${NC}"
else
    echo -e "${RED}✗ Docker compose up gagal${NC}"
    exit 1
fi

echo -e "${GREEN}--- Proses Selesai! ---${NC}"

# Tampilkan status container
echo -e "${YELLOW}--- Status Container ---${NC}"
docker compose ps

# Tampilkan logs terakhir (opsional)
echo -e "${YELLOW}--- Logs Aplikasi ---${NC}"
docker compose logs --tail=20
