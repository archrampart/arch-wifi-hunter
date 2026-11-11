#!/bin/bash
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

echo "=================================================="
echo "   ARCH // HUNTER - SETUP"
echo "=================================================="
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "   [!] Run as root: sudo ./setup.sh"
    exit 1
fi

# Check Python + venv
if ! command -v python3 &>/dev/null; then
    echo "   [!] Python3 not found. Install: apt install python3 python3-venv"
    exit 1
fi
python3 -m venv --help &>/dev/null || { echo "   [!] python3-venv missing. Run: apt install python3-venv"; exit 1; }

# Check Node
if ! command -v node &>/dev/null; then
    echo "   [!] Node.js not found. Install: apt install nodejs npm"
    exit 1
fi

# System tools check
echo "   [1/4] Checking system tools..."
MISSING=""
# tool_name -> apt_package mapping
declare -A TOOLS=(
    [aircrack-ng]=aircrack-ng
    [mdk4]=mdk4
    [hcxdumptool]=hcxdumptool
    [hcxpcapngtool]=hcxtools
    [reaver]=reaver
    [pixiewps]=pixiewps
    [nmap]=nmap
    [hostapd]=hostapd
    [dnsmasq]=dnsmasq
    [iptables]=iptables
)

MISSING_PKGS=""
for tool in "${!TOOLS[@]}"; do
    if ! command -v $tool &>/dev/null; then
        MISSING_PKGS="$MISSING_PKGS ${TOOLS[$tool]}"
        echo "         Missing: $tool (${TOOLS[$tool]})"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "         Installing..."
    apt install -y $MISSING_PKGS
else
    echo "         All system tools found"
fi

# Backend venv + dependencies
echo ""
echo "   [2/4] Setting up backend..."

# Ensure python3-venv and pip are available
apt install -y python3-venv python3-pip 2>/dev/null

if [ ! -f "backend/venv/bin/python" ]; then
    rm -rf backend/venv
    python3 -m venv backend/venv
    echo "         Virtual environment created"
else
    echo "         Virtual environment exists"
fi

# Verify venv works
if [ ! -f "backend/venv/bin/pip" ]; then
    echo "         [!] pip not found in venv, recreating..."
    rm -rf backend/venv
    python3 -m venv --clear backend/venv
fi

backend/venv/bin/pip install --upgrade pip -q
backend/venv/bin/pip install -r requirements.txt
echo "         Python dependencies installed"

# Verify uvicorn installed
if [ ! -f "backend/venv/bin/uvicorn" ]; then
    echo "         [!] uvicorn not found, installing directly..."
    backend/venv/bin/pip install uvicorn fastapi
fi

# Frontend
echo ""
echo "   [3/4] Installing frontend dependencies..."
cd frontend
npm install --silent 2>/dev/null
echo "         Node modules installed"

echo ""
echo "   [4/4] Building frontend..."
npm run build --silent 2>/dev/null
echo "         Frontend built"
cd "$PROJECT_ROOT"

# Create directories
mkdir -p backend/captures backend/exports wordlists

echo ""
echo "=================================================="
echo "   SETUP COMPLETE"
echo "   Run: sudo ./start.sh"
echo "=================================================="
