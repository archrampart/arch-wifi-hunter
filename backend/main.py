
from fastapi import FastAPI, WebSocket, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import asyncio
import json
from pydantic import BaseModel
from typing import Optional
from backend.attacks import AttackManager
from backend.cracker import Cracker
from backend.hunter import HunterAutomation
from backend.wifi_scanner import SafeScanner
from backend.serial_manager import serial_manager
from backend.ble_proximity import proximity_manager
from backend.ble_attack import BLEAttack
from backend.platform_wifi import IS_MACOS, IS_LINUX, PLATFORM, detect_wifi_interface
from backend.eviltwin import EvilTwinManager
from backend.pmkid import PMKIDManager
from backend.wps_attack import WPSManager
from backend.beacon_flood import BeaconFloodManager
from backend.unified_cracker import UnifiedCracker
from backend.mitm import MITMManager
import os
import queue
import subprocess
import time

app = FastAPI(title="WiFi Sniffer Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Managers
cracker = Cracker()
_wifi_interface = detect_wifi_interface()
attack_manager = AttackManager(interface=_wifi_interface)
hunter = HunterAutomation(attack_manager)
safe_scanner = SafeScanner(interface=_wifi_interface)

# Global State
log_queue = queue.Queue()

ble_state = {
    "scanning": False,
    "devices": [],
    "inspection_target": None,
    "inspection_result": {},
    "attack_running": False,
    "attack_result": {},
    "attack_target": None,
    "attack_type": None,
    "attack_options": {}
}
ble_attack = BLEAttack(ble_state, log_queue)
eviltwin_manager = EvilTwinManager(interface=_wifi_interface)
pmkid_manager = PMKIDManager(interface=_wifi_interface)
wps_manager = WPSManager(interface=_wifi_interface)
beacon_flood_manager = BeaconFloodManager(interface=_wifi_interface)
unified_cracker = UnifiedCracker()
mitm_manager = MITMManager()
safe_networks = []

class BLEResult(BaseModel):
    mac: str
    name: str
    rssi: int
    vendor: str
    distance: Optional[float] = None
    is_random_mac: bool = False
    random_mac_confidence: float = 0.0

class ProximityAlertRequest(BaseModel):
    mac: str
    threshold: float
    alert_type: str = "enter"  # "enter" or "exit"

# --- BLE AGENT API ---
@app.get("/ble/status")
def get_ble_status():
    status = {
        "scanning": ble_state["scanning"],
        "inspection_target": ble_state["inspection_target"],
        "reset_signal": ble_state.get("reset_signal", False)
    }
    # Auto-clear reset signal after it's been read? 
    # Or rely on client clearing. Let's keep it simple: Reset toggles off after 5s normally, 
    # but here we can just auto-toggle off in next logic or keep it momentary.
    # Actually, let's auto-clear it here to ensure it's a one-time command
    if ble_state.get("reset_signal"):
        ble_state["reset_signal"] = False
        
    return status

@app.post("/ble/results")
async def post_ble_results(devices: list[BLEResult]):
    # Convert Pydantic models to dicts
    ble_state["devices"] = [d.dict() for d in devices]
    return {"status": "ok"}

@app.post("/ble/inspection_result")
async def post_inspection_result(result: dict):
    ble_state["inspection_result"] = result
    # Clear target after receiving result so agent doesn't loop
    ble_state["inspection_target"] = None 
    return {"status": "ok"}

# --- FRONTEND API ---
@app.post("/ble/start")
async def start_ble():
    ble_state["scanning"] = True
    return {"status": "success", "message": "BLE Scan Started"}

@app.post("/ble/stop")
async def stop_ble():
    ble_state["scanning"] = False
    ble_state["inspection_target"] = None # Cancel inspection if stopping
    return {"status": "success", "message": "BLE Scan Stopped"}

class InspectionRequest(BaseModel):
    mac: str

@app.post("/ble/inspect")
async def inspect_ble(req: InspectionRequest):
    ble_state["inspection_target"] = req.mac
    ble_state["inspection_result"] = {} # Clear previous result
    return {"status": "success", "message": f"Inspection queued for {req.mac}"}

# --- BLE ATTACK API ---
class BLEAttackRequest(BaseModel):
    attack_type: str
    target_mac: Optional[str] = None
    options: Optional[dict] = None

@app.post("/ble/attack/start")
async def start_ble_attack(req: BLEAttackRequest):
    """Start BLE attack"""
    if ble_state["attack_running"]:
        return {"status": "error", "message": "An attack is already running"}

    valid_types = ["auto_connect", "pin_bruteforce", "fuzzing", "command_injection", "hijacking", "battery_drain", "beacon_spoof"]
    if req.attack_type not in valid_types:
        return {"status": "error", "message": f"Invalid attack type. Valid types: {', '.join(valid_types)}"}

    # Check if target is required
    no_target_types = ["auto_connect", "beacon_spoof"]
    if req.attack_type not in no_target_types and not req.target_mac:
        return {"status": "error", "message": "Target MAC address required for this attack"}

    ble_state["attack_type"] = req.attack_type
    ble_state["attack_target"] = req.target_mac
    ble_state["attack_options"] = req.options or {}
    ble_state["attack_running"] = True
    ble_state["attack_result"] = {}

    return {"status": "success", "message": f"Attack '{req.attack_type}' started"}

@app.post("/ble/attack/stop")
async def stop_ble_attack():
    """Stop current BLE attack"""
    ble_state["attack_running"] = False

    # If attack was in progress, mark result as stopped immediately
    if ble_state.get("attack_result") and ble_state["attack_result"].get("status") in ["running", "scanning"]:
        current_result = ble_state["attack_result"].copy()
        current_result["status"] = "stopped"
        current_result["message"] = current_result.get("message", "Attack stopped by user")
        ble_state["attack_result"] = current_result

    ble_state["attack_type"] = None
    ble_state["attack_options"] = {}
    return {"status": "success", "message": "Attack stopped"}

@app.get("/ble/attack/status")
async def get_ble_attack_status():
    """Get current attack status and results"""
    return {
        "status": "success",
        "running": ble_state["attack_running"],
        "attack_type": ble_state.get("attack_type"),
        "target": ble_state.get("attack_target"),
        "result": ble_state.get("attack_result", {})
    }

# --- PROXIMITY & MAC RANDOMIZATION API ---
@app.post("/ble/proximity/alert/add")
def add_proximity_alert(req: ProximityAlertRequest):
    """Add proximity alert for a BLE device"""
    try:
        proximity_manager.add_alert(req.mac, req.threshold, req.alert_type)
        return {"status": "success", "message": f"Alert added for {req.mac}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/ble/proximity/alert/remove")
def remove_proximity_alert(req: InspectionRequest):
    """Remove proximity alerts for a device"""
    try:
        proximity_manager.remove_alert(req.mac)
        return {"status": "success", "message": f"Alerts removed for {req.mac}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/ble/proximity/alerts")
def get_proximity_alerts():
    """Get triggered proximity alerts"""
    try:
        alerts = proximity_manager.get_triggered_alerts(clear=True)
        return {"status": "success", "alerts": alerts}
    except Exception as e:
        return {"status": "error", "message": str(e), "alerts": []}

@app.get("/ble/proximity/devices")
def get_proximity_devices():
    """Get all tracked devices with proximity info"""
    try:
        devices = proximity_manager.get_all_devices()
        return {"status": "success", "devices": devices}
    except Exception as e:
        return {"status": "error", "message": str(e), "devices": []}

@app.get("/ble/proximity/random_macs")
def get_random_mac_devices():
    """Get devices detected with MAC randomization"""
    try:
        devices = proximity_manager.get_random_mac_devices()
        return {"status": "success", "devices": devices}
    except Exception as e:
        return {"status": "error", "message": str(e), "devices": []}

@app.get("/ble/proximity/stats")
def get_proximity_stats():
    """Get proximity system statistics"""
    try:
        stats = proximity_manager.get_statistics()
        return {"status": "success", "stats": stats}
    except Exception as e:
        return {"status": "error", "message": str(e)}

class DeauthRequest(BaseModel):
    bssid: str
    client: str = None
    count: int = 5

@app.post("/attack/deauth")
def perform_deauth(req: DeauthRequest):
    # Only allow if we are locked on channel or it's just a quick burst
    # But usually we must be on same channel.
    # The attack_manager.send_deauth handles the actual injection.
    
    # Ensure interface is up? Handled by attack_manager.
    
    log_queue.put({"type": "log", "msg": f"Sending {req.count} Deauths to {req.bssid}..."})
    
    # Run in background to not block?
    # Deauth is usually fast (packets). 
    try:
        attack_manager.send_deauth(req.bssid, req.client, req.count)
        return {"status": "success", "message": "Deauth packets sent"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/scan/start")
def start_scan(background_tasks: BackgroundTasks):
    try:
        # Allow starting passive scan if we are idle OR if we are currently targeting (Unlocking)
        if not attack_manager.hopping:
            background_tasks.add_task(attack_manager.start_passive_scan)
            return {"status": "success", "message": "Scan started/resumed"}
        return {"status": "warning", "message": "Scan already hopping"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

class TargetRequest(BaseModel):
    channel: int

@app.post("/scan/target")
def target_scan(req: TargetRequest, background_tasks: BackgroundTasks):
    try:
        if hunter.running:
             return {"status": "error", "message": "Hunter Mode is Active. Disable it to manually lock targets."}
             
        # We can switch mode dynamically
        background_tasks.add_task(attack_manager.start_targeted_scan, req.channel)
        return {"status": "success", "message": f"Target locked on channel {req.channel}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/scan/stop")
def stop_scan():
    if hunter.running:
         hunter.stop()
    attack_manager.stop_scan()
    return {"status": "success", "message": "Scan stopped"}

# --- WIFI CLIENTS API ---
@app.get("/clients/list")
def get_wifi_clients():
    """Get list of all detected WiFi clients (devices)"""
    try:
        clients = []
        current_time = time.time()

        # Get clients from sniffer
        for mac, data in attack_manager.sniffer.wifi_clients.items():
            # Only show clients seen in last 60 seconds
            if current_time - data.get("last_seen", 0) < 60:
                clients.append({
                    "mac": mac,
                    "vendor": data.get("vendor", "Unknown"),
                    "signal": data.get("signal", -100),
                    "distance": data.get("distance", None),
                    "last_seen": data.get("last_seen", 0),
                    "probes": data.get("probes", []),
                    "connected_to": data.get("connected_to", None)
                })

        return {"status": "success", "clients": clients, "count": len(clients)}
    except Exception as e:
        return {"status": "error", "message": str(e), "clients": []}

@app.get("/clients/debug")
def debug_wifi_clients():
    """Debug endpoint to see all clients without time filter"""
    try:
        current_time = time.time()
        all_clients = []

        for mac, data in attack_manager.sniffer.wifi_clients.items():
            age = current_time - data.get("last_seen", 0)
            all_clients.append({
                "mac": mac,
                "vendor": data.get("vendor", "Unknown"),
                "signal": data.get("signal", -100),
                "distance": data.get("distance", None),
                "last_seen": data.get("last_seen", 0),
                "age_seconds": round(age, 1),
                "probes": data.get("probes", []),
                "connected_to": data.get("connected_to", None)
            })

        return {
            "status": "success",
            "total_clients": len(all_clients),
            "scanning_active": attack_manager.hopping or attack_manager.target_channel,
            "monitor_mode": attack_manager.hopping,
            "clients": all_clients
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- HUNTER API ---
@app.post("/hunter/start")
def start_hunter():
    if not hunter.running:
        hunter.start()
    return {"status": "started", "message": "Hunter Automation Started"}

@app.post("/hunter/stop")
def stop_hunter():
    hunter.stop()
    return {"status": "stopped", "message": "Hunter Automation Stopped"}

class CrackRequest(BaseModel):
    bssid: str
    ssid: str
    password: str = None # Optional for manual verify
    wordlist: str = "backend/wordlist.txt"



@app.post("/crack/start")
async def start_crack(req: CrackRequest, background_tasks: BackgroundTasks):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    
    # Resolve absolute path for wordlist
    wordlist_path = os.path.abspath(req.wordlist)
    if not os.path.isabs(req.wordlist):
        wordlist_path = os.path.join(project_root, req.wordlist)

    # Find capture file for this BSSID
    capture_dir = "backend/captures"
    # We look for handshake_XX-XX... or pmkid_XX-XX...
    
    target_file = None
    sanitized_bssid = req.bssid.replace(':', '-')
    
    # Priority 1: Handshake
    hs_file = os.path.join(capture_dir, f"handshake_{sanitized_bssid}.pcap")
    if os.path.exists(hs_file):
        target_file = hs_file
    
    # Priority 2: PMKID (if no handshake)
    if not target_file:
         pmk_file = os.path.join(capture_dir, f"pmkid_{sanitized_bssid}.pcap")
         if os.path.exists(pmk_file):
             target_file = pmk_file
             
    if not target_file:
        return {"status": "error", "message": "No capture file found for this network. Wait for PWNED status."}
    if not target_file:
        return {"status": "error", "message": "No capture file found. Verify 'PWNED' status."}
        
    # FORCE USE OF THE FOUND FILE
    pcap_path = target_file
    
    # We don't strictly need target_hs from memory if we have the file,
    # but we can look it up just for consistency or logging.
    # The crucial fix is using pcap_path = target_file.
    
    print(f"Starting Crack using Capture: {pcap_path}")

    # Check wordlist (User must provide valid path)
    if not os.path.exists(wordlist_path):
        return {"status": "error", "message": f"Wordlist not found: {wordlist_path}"}

    # Define callback to push to queue
    def log_callback(msg):
        log_queue.put({"type": "crack_log", "msg": msg})

    # Run cracking in a separate thread/executor to support streaming usage
    # We can use asyncio.to_thread in newer python, or loop.run_in_executor
    loop = asyncio.get_event_loop()
    
    # Send start log
    log_queue.put({"type": "crack_log", "msg": f"Starting Attack on {req.ssid}..."})
    
    # Execute
    res = await loop.run_in_executor(None, cracker.crack, pcap_path, wordlist_path, req.ssid, log_callback)
    
    # Send final result log
    if res["status"] == "success":
         log_queue.put({"type": "crack_log", "msg": f"SUCCESS: KEY FOUND: {res['key']}"})
         log_queue.put({"type": "crack_result", "status": "success", "key": res['key']})
    else:
         log_queue.put({"type": "crack_log", "msg": f"FAILED: {res.get('msg', 'Unknown error')}"})
         log_queue.put({"type": "crack_result", "status": "failed"})

    return res

@app.post("/crack/stop")
def stop_cracking():
    stopped = cracker.stop_crack()
    if stopped:
        log_queue.put({"type": "crack_log", "msg": "STOPPED: User terminated cracking session."})
        log_queue.put({"type": "crack_result", "status": "stopped"})
        return {"status": "success", "message": "Cracking stopped"}
    return {"status": "warning", "message": "No active cracking process found"}

class ExportRequest(BaseModel):
    bssid: str

@app.post("/crack/export")
async def export_capture(req: ExportRequest):
    # Find capture file
    target_hs = None
    for hs in attack_manager.sniffer.handshakes:
        if isinstance(hs, dict) and hs["bssid"] == req.bssid:
             target_hs = hs
             break
    
    if not target_hs or "file" not in target_hs:
        return {"status": "error", "message": "No capture found for this network"}
        
    pcap_path = target_hs["file"]
    if not os.path.exists(pcap_path):
        return {"status": "error", "message": "Capture file missing on disk"}
        
    # Generate Output Path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    export_dir = os.path.join(current_dir, "exports")
    os.makedirs(export_dir, exist_ok=True)
    
    ssid_clean = target_hs.get("ssid", "unknown").replace(" ", "_")
    output_filename = f"{ssid_clean}_{req.bssid.replace(':','')}.hccapx"
    output_path = os.path.join(export_dir, output_filename)
    
    # Run Conversion
    res = cracker.export_hccapx(pcap_path, output_path)
    
    if res["status"] == "success":
        return FileResponse(output_path, filename=output_filename, media_type='application/octet-stream')
    else:
        return {"status": "error", "message": res["msg"]}

# --- UNIFIED CRACK API ---
class UnifiedCrackRequest(BaseModel):
    bssid: str
    ssid: str
    wordlist: str = "wordlists/wordlist.txt"
    source_type: str = "auto"  # "auto", "handshake", "pmkid"

@app.post("/crack/unified/start")
async def start_unified_crack(req: UnifiedCrackRequest):
    """Unified crack endpoint - handles both handshake and PMKID sources."""
    if unified_cracker.cracking:
        return {"status": "error", "message": "Already cracking"}

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)

    # Resolve absolute path for wordlist
    wordlist_path = os.path.abspath(req.wordlist)
    if not os.path.isabs(req.wordlist):
        wordlist_path = os.path.join(project_root, req.wordlist)

    if not os.path.exists(wordlist_path):
        return {"status": "error", "message": f"Wordlist not found: {wordlist_path}"}

    def log_callback(msg):
        log_queue.put({"type": "crack_log", "msg": msg})

    def progress_callback(progress_data):
        log_queue.put({"type": "crack_progress", **progress_data})

    log_queue.put({"type": "crack_log", "msg": f"Starting unified crack on {req.ssid} ({req.source_type})..."})

    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(
        None, unified_cracker.crack,
        req.bssid, req.ssid, wordlist_path, req.source_type, log_callback, progress_callback
    )

    if res["status"] == "success":
        log_queue.put({"type": "crack_log", "msg": f"SUCCESS: KEY FOUND: {res['key']}"})
        log_queue.put({"type": "crack_result", "status": "success", "key": res['key']})
    elif res["status"] == "failed":
        log_queue.put({"type": "crack_log", "msg": f"FAILED: {res.get('msg', 'Unknown error')}"})
        log_queue.put({"type": "crack_result", "status": "failed"})
    else:
        log_queue.put({"type": "crack_log", "msg": f"ERROR: {res.get('msg', 'Unknown error')}"})
        log_queue.put({"type": "crack_result", "status": "error"})

    return res

@app.post("/crack/unified/stop")
def stop_unified_crack():
    """Stop unified cracking."""
    stopped = unified_cracker.stop()
    if stopped:
        log_queue.put({"type": "crack_log", "msg": "STOPPED: User terminated cracking session."})
        log_queue.put({"type": "crack_result", "status": "stopped"})
        return {"status": "success", "message": "Cracking stopped"}
    return {"status": "warning", "message": "No active cracking process found"}

@app.get("/crack/history")
def get_crack_history():
    """Get crack history."""
    return {"status": "success", "history": unified_cracker.get_history()}

@app.post("/crack/history/clear")
def clear_crack_history():
    """Clear crack history."""
    unified_cracker.history = []
    unified_cracker._save_history()
    return {"status": "success", "message": "History cleared"}

@app.get("/crack/targets")
def get_crack_targets():
    """List all crackable targets (networks with capture files)."""
    return {"status": "success", "targets": unified_cracker.get_targets()}

@app.post("/crack/targets/delete")
def delete_crack_target(req: dict):
    """Delete a crackable target and its capture files."""
    bssid = req.get("bssid", "")
    if not bssid:
        return {"status": "error", "message": "BSSID required"}
    sanitized = bssid.replace(":", "-")
    capture_dir = os.path.join(os.path.dirname(__file__), "captures")
    deleted = []
    patterns = [
        f"handshake_{sanitized}.pcap",
        f"pmkid_{sanitized}.22000",
        f"pmkid_{sanitized}.pcap",
        f"pmkid_{sanitized}.cap",
    ]
    for fname in patterns:
        fpath = os.path.join(capture_dir, fname)
        if os.path.exists(fpath):
            os.remove(fpath)
            deleted.append(fname)
    return {"status": "success", "deleted": deleted, "bssid": bssid}

@app.get("/crack/wordlists")
def list_wordlists():
    """List available wordlist files from wordlists/ directory."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wl_dir = os.path.join(project_root, "wordlists")
    files = []
    if os.path.isdir(wl_dir):
        for f in sorted(os.listdir(wl_dir)):
            fp = os.path.join(wl_dir, f)
            if os.path.isfile(fp) and not f.startswith('.'):
                size = os.path.getsize(fp)
                files.append({"name": f, "path": f"wordlists/{f}", "size": size})
    return {"status": "success", "wordlists": files}


async def safe_scan_loop():
    """Runs passive scan periodically when not in Attack/Monitor mode"""
    global safe_networks
    while True:
        # Skip scan if Evil Twin, PMKID, or WPS is running/starting (they use the interface)
        if eviltwin_manager.running or eviltwin_manager.starting or pmkid_manager.running or pmkid_manager.starting or wps_manager.running or wps_manager.starting or beacon_flood_manager.running or beacon_flood_manager.starting:
            await asyncio.sleep(2)
            continue

        # Only run if Attack Manager is idle to avoid conflicts
        if not attack_manager.hopping and not attack_manager.target_channel:
            try:
                loop = asyncio.get_running_loop()
                nets = await loop.run_in_executor(None, safe_scanner.scan)
                if nets:
                    safe_networks = nets

            except Exception as e:
                print(f"Safe Scan Error: {e}")

        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    # Start safe scan loop
    asyncio.create_task(safe_scan_loop())
    # Start BLE Attack loop
    asyncio.create_task(ble_attack.run_loop())
    # Start BLE Scan automatically if needed, or leave to user
    # ble_state["scanning"] = True 

# ... (Previous API endpoints)

# ==========================================
# GPIO / SERIAL ROUTES
# ==========================================
@app.api_route("/serial/list", methods=["GET", "POST"])
def serial_list():
    return {"ports": serial_manager.list_ports()}

@app.post("/serial/connect")
def serial_connect(data: dict):
    port = data.get("port")
    baud = int(data.get("baud", 115200))
    success, msg = serial_manager.connect(port, baud)
    return {"status": "success" if success else "error", "message": msg}

@app.post("/serial/auto_connect")
def serial_auto_connect():
    success, msg = serial_manager.auto_connect()
    return {"status": "success" if success else "error", "message": msg}

@app.api_route("/serial/status", methods=["GET", "POST"])
def serial_status():
    return {"connected": serial_manager.is_connected, "device": serial_manager.serial_port.port if serial_manager.is_connected else None}

@app.post("/serial/disconnect")
def serial_disconnect():
    serial_manager.disconnect()
    return {"status": "success"}

@app.post("/serial/write")
def serial_write(data: dict):
    cmd = data.get("cmd", "")
    success, msg = serial_manager.write(cmd)
    return {"status": "success" if success else "error", "message": msg}

@app.api_route("/serial/logs", methods=["GET", "POST"])
def serial_logs():
    try:
        return {"logs": serial_manager.get_logs()}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"logs": [f"[SYSTEM ERROR] {str(e)}"]}

@app.post("/system/wifi_reset")
def system_wifi_reset():
    try:
        # Kill running processes
        subprocess.run(["pkill", "-f", "tcpdump"], stderr=subprocess.DEVNULL)

        iface = attack_manager.interface

        if IS_MACOS:
            subprocess.run(["pkill", "-f", "airport"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "airportd"], stderr=subprocess.DEVNULL)
            # Power Cycle via NetworkSetup
            subprocess.run(["networksetup", "-setairportpower", iface, "off"])
            time.sleep(2)
            subprocess.run(["networksetup", "-setairportpower", iface, "on"])
            time.sleep(2)
        else:
            # Linux: stop monitor mode, kill aircrack processes, bring interface back up
            subprocess.run(["pkill", "-f", "airodump"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "aireplay"], stderr=subprocess.DEVNULL)
            subprocess.run(["airmon-ng", "stop", iface], stderr=subprocess.DEVNULL)
            time.sleep(1)
            # Restore original interface
            orig_iface = attack_manager.monitor.original_interface
            subprocess.run(["ip", "link", "set", orig_iface, "up"], stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "start", "NetworkManager"], stderr=subprocess.DEVNULL)
            time.sleep(2)
            # Update interface references
            attack_manager.interface = orig_iface
            attack_manager.monitor.interface = orig_iface
            attack_manager.sniffer.interface = orig_iface

        # CLEAR INTERNAL CACHE
        attack_manager.sniffer.access_points = {}
        attack_manager.sniffer.handshakes = []
        attack_manager.sniffer.beacon_cache = {}

        return {"status": "success", "message": "WiFi Hardware Reset & Cache Cleared."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/system/reset")
def system_reset():
    global ble_state, safe_networks
    
    # 1. Clear In-Memory State
    ble_state["devices"] = []
    ble_state["inspection_target"] = None
    ble_state["inspection_result"] = {}
    ble_state["reset_signal"] = True # Notify Agent to Clear Cache
    safe_networks = []
    
    # 2. Reset Attack Manager State
    if attack_manager.hopping:
        attack_manager.stop_scan()
    
    if hasattr(attack_manager, 'sniffer'):
        attack_manager.sniffer.ap_results = {}
        attack_manager.sniffer.handshakes = []
        attack_manager.sniffer.clients = {}

    # 3. Clear Files (Keep directory, delete contents)
    folders = ["captures", "exports", "backend/captures", "backend/exports"]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    for folder in folders:
        folder_path = os.path.join(project_root, folder)
        if os.path.exists(folder_path):
            try:
                for filename in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, filename)
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
            except Exception as e:
                print(f"Failed to delete {folder_path}: {e}")

    return {"status": "success", "message": "Factory Reset Complete"}

@app.get("/system/select_file")
async def select_wordlist_file():
    """
    Opens a native file dialog to select a wordlist.
    macOS: osascript, Linux: zenity
    Returns the absolute path.
    """
    try:
        sudo_user = os.environ.get('SUDO_USER')

        if IS_MACOS:
            script = 'choose file with prompt "Select Wordlist File" of type {"txt", "lst", "dic"}'
            if sudo_user:
                cmd = ["sudo", "-u", sudo_user, "osascript", "-e", f'POSIX path of ({script})']
            else:
                cmd = ["osascript", "-e", f'POSIX path of ({script})']
        else:
            # Linux: use zenity if available
            if sudo_user:
                cmd = ["sudo", "-u", sudo_user, "zenity", "--file-selection", "--title=Select Wordlist File",
                       "--file-filter=Wordlists | *.txt *.lst *.dic"]
            else:
                cmd = ["zenity", "--file-selection", "--title=Select Wordlist File",
                       "--file-filter=Wordlists | *.txt *.lst *.dic"]

        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            path = stdout.decode().strip()
            return {"status": "success", "path": path}
        else:
            return {"status": "canceled", "message": "User canceled selection."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- EVIL TWIN API ---
class EvilTwinRequest(BaseModel):
    ssid: str
    bssid: str
    channel: int
    portal_type: str = "generic"
    mode: str = "captive_portal"

@app.post("/eviltwin/start")
def start_eviltwin(req: EvilTwinRequest, background_tasks: BackgroundTasks):
    """Start Evil Twin attack."""
    if eviltwin_manager.running:
        return {"status": "error", "message": "Evil Twin already running"}

    if wps_manager.running or wps_manager.starting:
        return {"status": "error", "message": "Cannot start Evil Twin while WPS attack is active"}

    if beacon_flood_manager.running or beacon_flood_manager.starting:
        return {"status": "error", "message": "Cannot start Evil Twin while Beacon Flood is active"}

    # Stop any running WiFi scan first
    if attack_manager.hopping:
        attack_manager.stop_scan()

    result = eviltwin_manager.start(req.ssid, req.bssid, req.channel, req.portal_type, req.mode)
    return result

@app.post("/eviltwin/stop")
def stop_eviltwin():
    """Stop Evil Twin attack."""
    result = eviltwin_manager.stop()
    return result

@app.get("/eviltwin/status")
def get_eviltwin_status():
    """Get Evil Twin attack status."""
    return {"status": "success", **eviltwin_manager.get_status()}

@app.get("/eviltwin/creds")
def get_eviltwin_creds():
    """Get captured credentials."""
    return {"status": "success", "credentials": eviltwin_manager.get_credentials()}

@app.post("/eviltwin/creds/clear")
def clear_eviltwin_creds():
    """Clear captured credentials."""
    eviltwin_manager.clear_credentials()
    return {"status": "success", "message": "Credentials cleared"}

# --- MITM API ---
class MITMSnifferRequest(BaseModel):
    filter_mode: str = "all"

class DNSSpoofEntry(BaseModel):
    domain: str
    ip: str

class DNSSpoofRemoveRequest(BaseModel):
    domain: str

@app.post("/mitm/sniffer/start")
def start_mitm_sniffer(req: MITMSnifferRequest):
    """Start MITM packet sniffer (requires Evil Twin running in internet_relay mode)."""
    if not eviltwin_manager.running:
        return {"status": "error", "message": "Evil Twin must be running first"}
    interface = eviltwin_manager.interface
    result = mitm_manager.sniffer.start(interface, req.filter_mode)
    return result

@app.post("/mitm/sniffer/stop")
def stop_mitm_sniffer():
    """Stop MITM sniffer."""
    return mitm_manager.sniffer.stop()

@app.get("/mitm/sniffer/packets")
def get_mitm_packets(offset: int = 0, limit: int = 100, filter_type: str = "all"):
    """Get captured packets with pagination."""
    return mitm_manager.sniffer.get_packets(offset, limit, filter_type)

@app.get("/mitm/sniffer/stats")
def get_mitm_stats():
    """Get sniffer statistics."""
    return {"status": "success", **mitm_manager.sniffer.get_stats()}

@app.post("/mitm/sniffer/export")
def export_mitm_pcap():
    """Export captured packets to PCAP file."""
    result = mitm_manager.sniffer.export_pcap()
    if result["status"] == "success":
        filepath = result["filepath"]
        filename = os.path.basename(filepath)
        return FileResponse(filepath, filename=filename, media_type='application/octet-stream')
    return result

@app.post("/mitm/dns-spoof/add")
def add_dns_spoof(req: DNSSpoofEntry):
    """Add DNS spoof entry."""
    return mitm_manager.dns_spoof.add_entry(req.domain, req.ip)

@app.post("/mitm/dns-spoof/remove")
def remove_dns_spoof(req: DNSSpoofRemoveRequest):
    """Remove DNS spoof entry."""
    return mitm_manager.dns_spoof.remove_entry(req.domain)

@app.get("/mitm/dns-spoof/list")
def list_dns_spoof():
    """List DNS spoof entries."""
    return {"status": "success", "entries": mitm_manager.dns_spoof.get_entries()}

@app.post("/mitm/dns-spoof/start")
def start_dns_spoof():
    """Start DNS spoofing."""
    if not eviltwin_manager.running:
        return {"status": "error", "message": "Evil Twin must be running first"}
    return mitm_manager.dns_spoof.start()

@app.post("/mitm/dns-spoof/stop")
def stop_dns_spoof():
    """Stop DNS spoofing."""
    return mitm_manager.dns_spoof.stop()

@app.get("/mitm/status")
def get_mitm_status():
    """Get combined MITM status."""
    return {"status": "success", **mitm_manager.get_status()}

# --- PMKID CAPTURE API ---
class PMKIDRequest(BaseModel):
    bssid: str
    ssid: str
    channel: int
    timeout: int = 60

@app.post("/pmkid/start")
def start_pmkid(req: PMKIDRequest):
    """Start PMKID capture."""
    if pmkid_manager.running:
        return {"status": "error", "message": "PMKID capture already running"}

    # Mutual exclusion with Evil Twin and WPS
    if eviltwin_manager.running or eviltwin_manager.starting:
        return {"status": "error", "message": "Cannot start PMKID while Evil Twin is active"}

    if wps_manager.running or wps_manager.starting:
        return {"status": "error", "message": "Cannot start PMKID while WPS attack is active"}

    if beacon_flood_manager.running or beacon_flood_manager.starting:
        return {"status": "error", "message": "Cannot start PMKID while Beacon Flood is active"}

    # Stop any running WiFi scan first
    if attack_manager.hopping:
        attack_manager.stop_scan()

    result = pmkid_manager.start(req.bssid, req.ssid, req.channel, req.timeout)
    return result

@app.post("/pmkid/stop")
def stop_pmkid():
    """Stop PMKID capture."""
    result = pmkid_manager.stop()
    return result

@app.get("/pmkid/status")
def get_pmkid_status():
    """Get PMKID capture status."""
    return {"status": "success", **pmkid_manager.get_status()}

@app.get("/pmkid/results")
def get_pmkid_results():
    """Get captured PMKID results."""
    return {"status": "success", "results": pmkid_manager.get_results()}

class PMKIDCrackRequest(BaseModel):
    bssid: str
    ssid: str
    wordlist: str = "wordlists/wordlist.txt"

@app.post("/pmkid/crack/start")
async def start_pmkid_crack(req: PMKIDCrackRequest):
    """Start cracking a PMKID hash with aircrack-ng."""
    if pmkid_manager.cracking:
        return {"status": "error", "message": "Already cracking"}

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)

    # Resolve wordlist path
    wordlist_path = os.path.abspath(req.wordlist)
    if not os.path.isabs(req.wordlist):
        wordlist_path = os.path.join(project_root, req.wordlist)

    if not os.path.exists(wordlist_path):
        return {"status": "error", "message": f"Wordlist not found: {wordlist_path}"}

    def log_callback(msg):
        log_queue.put({"type": "pmkid_crack_log", "msg": msg})

    log_queue.put({"type": "pmkid_crack_log", "msg": f"Starting crack on {req.ssid} ({req.bssid})..."})

    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, pmkid_manager.crack, req.bssid, req.ssid, wordlist_path, log_callback)

    if res.get("status") == "success":
        log_queue.put({"type": "pmkid_crack_log", "msg": f"SUCCESS: KEY FOUND: {res['key']}"})
        log_queue.put({"type": "pmkid_crack_result", "status": "success", "key": res['key']})
    else:
        log_queue.put({"type": "pmkid_crack_log", "msg": f"FAILED: {res.get('msg', 'Unknown error')}"})
        log_queue.put({"type": "pmkid_crack_result", "status": "failed"})

    return res

@app.post("/pmkid/crack/stop")
def stop_pmkid_crack():
    """Stop PMKID cracking."""
    stopped = pmkid_manager.stop_crack()
    if stopped:
        log_queue.put({"type": "pmkid_crack_log", "msg": "STOPPED: User terminated cracking session."})
        log_queue.put({"type": "pmkid_crack_result", "status": "stopped"})
        return {"status": "success", "message": "Cracking stopped"}
    return {"status": "warning", "message": "No active cracking process found"}

# --- WPS ATTACK API ---
class WPSRequest(BaseModel):
    bssid: str
    ssid: str
    channel: int
    attack_type: str = "pixie_dust"

@app.post("/wps/start")
def start_wps(req: WPSRequest, background_tasks: BackgroundTasks):
    """Start WPS attack."""
    if wps_manager.running or wps_manager.starting:
        return {"status": "error", "message": "WPS attack already running"}

    # Mutual exclusion
    if eviltwin_manager.running or eviltwin_manager.starting:
        return {"status": "error", "message": "Cannot start WPS while Evil Twin is active"}

    if pmkid_manager.running or pmkid_manager.starting:
        return {"status": "error", "message": "Cannot start WPS while PMKID capture is active"}

    if beacon_flood_manager.running or beacon_flood_manager.starting:
        return {"status": "error", "message": "Cannot start WPS while Beacon Flood is active"}

    # Stop any running WiFi scan first
    if attack_manager.hopping:
        attack_manager.stop_scan()

    def log_callback(msg):
        log_queue.put({"type": "wps_log", "msg": msg})

    result = wps_manager.start(
        req.bssid, req.ssid, req.channel,
        attack_type=req.attack_type,
        callback=log_callback
    )
    return result

@app.post("/wps/stop")
def stop_wps():
    """Stop WPS attack."""
    result = wps_manager.stop()
    log_queue.put({"type": "wps_log", "msg": "STOPPED: User terminated WPS attack."})
    return result

@app.get("/wps/status")
def get_wps_status():
    """Get WPS attack status."""
    return {"status": "success", **wps_manager.get_status()}

@app.get("/wps/results")
def get_wps_results():
    """Get recovered WPS PINs/passwords."""
    return {"status": "success", "results": wps_manager.get_results()}

# --- BEACON FLOOD API ---
class BeaconFloodRequest(BaseModel):
    ssid_list: list[str] = []
    channel: int = 0
    speed: int = 50
    mode: str = "random"

@app.post("/flood/start")
def start_flood(req: BeaconFloodRequest):
    """Start beacon flood attack."""
    if beacon_flood_manager.running or beacon_flood_manager.starting:
        return {"status": "error", "message": "Beacon flood already running"}

    # Mutual exclusion
    if eviltwin_manager.running or eviltwin_manager.starting:
        return {"status": "error", "message": "Cannot start Beacon Flood while Evil Twin is active"}

    if pmkid_manager.running or pmkid_manager.starting:
        return {"status": "error", "message": "Cannot start Beacon Flood while PMKID capture is active"}

    if wps_manager.running or wps_manager.starting:
        return {"status": "error", "message": "Cannot start Beacon Flood while WPS attack is active"}

    if hunter.running:
        return {"status": "error", "message": "Cannot start Beacon Flood while Hunter is active"}

    # Stop any running WiFi scan first
    if attack_manager.hopping:
        attack_manager.stop_scan()

    print(f"[FLOOD-API] /flood/start called: mode={req.mode}, ssids={len(req.ssid_list)}, "
          f"channel={req.channel}, speed={req.speed}, interface={beacon_flood_manager.interface}")

    def log_callback(msg):
        print(f"[FLOOD-CB] {msg}")
        log_queue.put({"type": "flood_log", "msg": msg})

    result = beacon_flood_manager.start(
        ssid_list=req.ssid_list if req.ssid_list else None,
        channel=req.channel,
        speed=req.speed,
        mode=req.mode,
        callback=log_callback
    )
    print(f"[FLOOD-API] start() returned: {result}")
    return result

@app.post("/flood/stop")
def stop_flood():
    """Stop beacon flood attack."""
    result = beacon_flood_manager.stop()
    log_queue.put({"type": "flood_log", "msg": "STOPPED: User terminated beacon flood."})
    return result

@app.get("/flood/status")
def get_flood_status():
    """Get beacon flood status."""
    return {"status": "success", **beacon_flood_manager.get_status()}

@app.get("/system/platform")
def get_platform_info():
    """Returns current platform information."""
    return {
        "platform": PLATFORM,
        "is_macos": IS_MACOS,
        "is_linux": IS_LINUX,
        "interface": attack_manager.interface
    }



@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Prepare Data
            payload = {
                "type": "scan_update",
                "aps": 0,
                "handshakes": 0,
                "mode": "IDLE",
                "networks": [],
                "ble_devices": ble_state["devices"],
                "ble_active": ble_state["scanning"],
                "ble_inspection": ble_state["inspection_result"],
                "hunter_status": {
                    "running": hunter.running,
                    "status": hunter.status,
                    "visited_count": len(hunter.visited_bssids)
                },
                "wifi_clients": [],  # WiFi clients data
                "proximity_alerts": [],  # NEW: Proximity alerts
                "proximity_stats": {},  # NEW: Proximity stats
                "eviltwin_status": eviltwin_manager.get_status(),
                "pmkid_status": pmkid_manager.get_status(),
                "wps_status": wps_manager.get_status(),
                "flood_status": beacon_flood_manager.get_status(),
                "crack_status": unified_cracker.get_status(),
                "mitm_status": mitm_manager.get_status()
            }

            # Get proximity alerts and stats
            try:
                payload["proximity_alerts"] = proximity_manager.get_triggered_alerts(clear=False)
                payload["proximity_stats"] = proximity_manager.get_statistics()
            except:
                pass

            # NEW: Collect WiFi clients
            current_time = time.time()
            wifi_clients = []
            try:
                for mac, data in attack_manager.sniffer.wifi_clients.items():
                    # Only include clients seen in last 60 seconds
                    if current_time - data.get("last_seen", 0) < 60:
                        wifi_clients.append({
                            "mac": mac,
                            "vendor": data.get("vendor", "Unknown"),
                            "signal": data.get("signal", -100),
                            "distance": data.get("distance", None),
                            "last_seen": data.get("last_seen", 0),
                            "probes": data.get("probes", []),
                            "connected_to": data.get("connected_to", None)
                        })
                payload["wifi_clients"] = wifi_clients
            except:
                pass  # If sniffer not initialized, skip

            # If Monitor Mode active (Hopping or Targeted), use live Sniffer data
            if attack_manager.hopping or attack_manager.target_channel:
                results = attack_manager.get_results()
                payload.update({
                    "aps": len(results["aps"]),
                    "handshakes": len(results["handshakes"]),
                    "mode": results["current_channel"], 
                    "networks": [
                        {
                            "bssid": k,
                            "ssid": v["ssid"],
                            "signal": v["signal"],
                            "channel": v.get("channel", 0),
                            "pwned": any(h.get("bssid") == k for h in results["handshakes"] if isinstance(h, dict)),
                            "band": "5GHz" if v.get("channel", 0) > 14 else ("2.4GHz" if v.get("channel", 0) > 0 else "?"),
                            "wps": v.get("wps_support", False), # Assuming sniffer has this
                            "clients": v.get("clients", {}),
                            "pmkid": v.get("pmkid", False),
                            "is_evil_twin": v.get("is_evil_twin", False)
                        } for k, v in results["aps"].items()
                    ]
                })
            else:
                # Use Safe Scan Data
                payload["mode"] = "PASSIVE"
                payload["aps"] = len(safe_networks)
                payload["networks"] = safe_networks
            
            await websocket.send_json(payload)
            
            # Flush Log Queue
            while not log_queue.empty():
                log_msg = log_queue.get()
                await websocket.send_json(log_msg)
            
            await asyncio.sleep(0.5)
    except Exception as e:
        print(f"WebSocket Client Disconnected: {e}")
