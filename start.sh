#!/bin/bash
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

# Single port: FastAPI serves both the built frontend (UI) and the API.
PORT=8777
HOST=0.0.0.0

echo "=================================================="
echo "   ARCH // HUNTER - STARTING"
echo "=================================================="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "   [!] Run as root: sudo ./start.sh"
    exit 1
fi

# Check setup
if [ ! -d "backend/venv" ]; then
    echo "   [!] Run setup first: sudo ./setup.sh"
    exit 1
fi

# Build the frontend once if it hasn't been built yet (served by FastAPI)
if [ ! -f "frontend/dist/index.html" ]; then
    echo "   [*] Building frontend (first run)..."
    ( cd frontend && npm install --silent 2>/dev/null && npm run build 2>&1 | tail -2 )
fi

cleanup() {
    echo ""
    echo "=================================================="
    echo "   Shutting down..."
    echo "=================================================="

    pkill -f ble_agent.py 2>/dev/null
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    # Stop any monitor mode interfaces
    for mon in $(iw dev 2>/dev/null | grep -oP 'Interface \K\S+mon'); do
        airmon-ng stop "$mon" 2>/dev/null
    done
    # Ensure NetworkManager is running (Evil Twin captive-portal mode stops it)
    systemctl start NetworkManager 2>/dev/null

    echo "   Shutdown complete"
    echo "=================================================="
    exit
}

trap cleanup SIGINT EXIT

# Detect LAN IP for display
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP="localhost"

# Start BLE Agent (D-Bus pairing helper)
echo "   [1/2] Starting BLE Agent..."
"$PROJECT_ROOT/backend/venv/bin/python" "$PROJECT_ROOT/backend/ble_agent.py" &

# Start Server (UI + API on one port)
echo "   [2/2] Starting Server..."
echo ""
echo "=================================================="
echo "   ARCH // HUNTER READY"
echo "   URL  : http://${IP}:${PORT}"
echo "   Docs : http://${IP}:${PORT}/docs"
echo "   Press Ctrl+C to stop"
echo "=================================================="
echo ""

"$PROJECT_ROOT/backend/venv/bin/uvicorn" backend.main:app --host "$HOST" --port "$PORT"
