#!/bin/bash
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

echo "=================================================="
echo "   ARCH // HUNTER - STARTING"
echo "=================================================="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "   [!] Run as root: sudo ./start.sh"
    exit 1
fi

# Check setup
if [ ! -d "backend/venv" ] || [ ! -d "frontend/node_modules" ]; then
    echo "   [!] Run setup first: sudo ./setup.sh"
    exit 1
fi

cleanup() {
    echo ""
    echo "=================================================="
    echo "   Shutting down..."
    echo "=================================================="

    [ -n "$FRONTEND_PID" ] && kill $FRONTEND_PID 2>/dev/null
    pkill -f ble_agent.py 2>/dev/null
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    # Stop any monitor mode interfaces
    for mon in $(iw dev 2>/dev/null | grep -oP 'Interface \K\S+mon'); do
        airmon-ng stop "$mon" 2>/dev/null
    done
    systemctl start NetworkManager 2>/dev/null

    VITE_PID=$(ss -tlnp 2>/dev/null | grep ':5173' | grep -oP 'pid=\K[0-9]+' || fuser 5173/tcp 2>/dev/null)
    [ -n "$VITE_PID" ] && kill -9 $VITE_PID 2>/dev/null

    echo "   Shutdown complete"
    echo "=================================================="
    exit
}

trap cleanup SIGINT EXIT

# Start Frontend
echo "   [1/3] Starting Frontend..."
cd frontend
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd "$PROJECT_ROOT"

for i in {1..30}; do
    curl -s http://localhost:5173 > /dev/null 2>&1 && break
    sleep 0.5
done

# Start BLE Agent
echo "   [2/3] Starting BLE Agent..."
"$PROJECT_ROOT/backend/venv/bin/python" "$PROJECT_ROOT/backend/ble_agent.py" &

# Start Backend
echo "   [3/3] Starting Backend..."
echo ""
echo "=================================================="
echo "   ARCH // HUNTER READY"
echo "   Frontend : http://localhost:5173"
echo "   API      : http://localhost:8000"
echo "   Docs     : http://localhost:8000/docs"
echo "   Press Ctrl+C to stop"
echo "=================================================="
echo ""

"$PROJECT_ROOT/backend/venv/bin/uvicorn" backend.main:app --host 0.0.0.0 --port 8000
