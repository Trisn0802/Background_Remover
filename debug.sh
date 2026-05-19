#!/bin/bash

# Debug script untuk troubleshooting

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== BACKGROUND REMOVER DEBUG SCRIPT ===${NC}\n"

# 1. Check bash version
echo -e "${YELLOW}[1] Bash Version:${NC}"
bash --version | head -1
echo ""

# 2. Check OS
echo -e "${YELLOW}[2] OS Info:${NC}"
uname -a
echo ""

# 3. Check Docker
echo -e "${YELLOW}[3] Docker Status:${NC}"
if command -v docker &> /dev/null; then
    docker --version
    docker ps -a --format "table {{.Names}}\t{{.Status}}"
else
    echo -e "${RED}✗ Docker not found${NC}"
fi
echo ""

# 4. Check Docker Compose
echo -e "${YELLOW}[4] Docker Compose:${NC}"
if command -v docker compose &> /dev/null; then
    docker compose version
else
    echo -e "${RED}✗ Docker Compose not found${NC}"
fi
echo ""

# 5. Check repo directory
echo -e "${YELLOW}[5] Repository Directory:${NC}"
REPO_DIR="/var/www/docker/app/Background_Remover"
if [ -d "$REPO_DIR" ]; then
    echo -e "${GREEN}✓ Directory exists: $REPO_DIR${NC}"
    if [ -d "$REPO_DIR/.git" ]; then
        echo -e "${GREEN}✓ Git repo found${NC}"
        cd "$REPO_DIR"
        echo "  Git status: $(git status --porcelain | wc -l) changes"
        echo "  Current branch: $(git branch --show-current)"
        echo "  Remote URL: $(git remote get-url origin)"
    else
        echo -e "${RED}✗ Not a git repository${NC}"
    fi
else
    echo -e "${RED}✗ Directory not found: $REPO_DIR${NC}"
fi
echo ""

# 6. Check .env file
echo -e "${YELLOW}[6] Environment File:${NC}"
if [ -f "$REPO_DIR/.env" ]; then
    echo -e "${GREEN}✓ .env exists${NC}"
    echo "  Keys set:"
    grep "^[^#]" "$REPO_DIR/.env" | sed 's/=.*/=***/' | sed 's/^/    /'
else
    echo -e "${RED}✗ .env not found${NC}"
fi
echo ""

# 7. Check permissions
echo -e "${YELLOW}[7] Permissions:${NC}"
echo "  User: $(whoami)"
echo "  Groups: $(groups | tr ' ' ', ')"
if [ -w "$REPO_DIR" ]; then
    echo -e "${GREEN}✓ Write permission OK${NC}"
else
    echo -e "${RED}✗ No write permission${NC}"
fi
echo ""

# 8. Check Log file
echo -e "${YELLOW}[8] Log File:${NC}"
LOG_FILE="/var/log/bg-remover-update.log"
if [ -f "$LOG_FILE" ]; then
    echo -e "${GREEN}✓ Log exists: $LOG_FILE${NC}"
    echo "  Size: $(du -h "$LOG_FILE" | cut -f1)"
    echo "  Last 10 lines:"
    tail -10 "$LOG_FILE" | sed 's/^/    /'
else
    echo "  Log file not created yet"
fi
echo ""

# 9. Check container logs
echo -e "${YELLOW}[9] Container Logs:${NC}"
if [ -d "$REPO_DIR" ]; then
    cd "$REPO_DIR"
    if docker compose ps &> /dev/null; then
        echo "  Docker compose status:"
        docker compose ps | sed 's/^/    /'
        echo ""
        echo "  Recent app logs:"
        docker compose logs --tail=20 app 2>/dev/null | sed 's/^/    /' || echo "    (no logs available)"
    fi
fi
echo ""

# 10. Check disk space
echo -e "${YELLOW}[10] Disk Space:${NC}"
df -h "$REPO_DIR" 2>/dev/null | tail -1 | awk '{printf "  Available: %s\n", $4}'
echo ""

# Summary
echo -e "${BLUE}=== NEXT STEPS ===${NC}"
echo -e "1. Check if REPO_URL is correct in update_and_run.sh"
echo -e "2. Check .env file has all required variables"
echo -e "3. Check log file for detailed errors:"
echo -e "   ${YELLOW}tail -f $LOG_FILE${NC}"
echo -e "4. Try running update script again:"
echo -e "   ${YELLOW}cd $REPO_DIR && ./update_and_run.sh${NC}"
echo ""
