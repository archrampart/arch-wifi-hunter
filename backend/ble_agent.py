import asyncio
import aiohttp
from bleak import BleakScanner, BleakClient
import sys
import os

# Add parent directory to path for imports when running as standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.oui_lookup import lookup_mac_vendor
from backend.ble_proximity import proximity_manager

# ===================================================================================
# 🔒 CRITICAL: BLE SCANNING & INSPECTION LOGIC - LOCKED (STABLE CONFIGURATION - JAN 2026) 🔒
# ===================================================================================
# DO NOT MODIFY THIS FILE WITHOUT EXPLICIT "DOUBLE" USER APPROVAL.
# This agent handles:
# 1. Continuous BLE Scanning (Background)
# 2. Deep Device Inspection (Services, Battery, Info)
# 3. Vendor Identification (Apple, Microsoft, etc.)
# 4. Backend Communication (Posting results to API)
#
# ANY CHANGES HERE MAY BREAK THE BLE RADAR OR WATCH FEATURES.
# ===================================================================================

BACKEND_URL = "http://localhost:8000"


# Common BLE Vendor IDs
VENDOR_IDS = {
    76: "Apple",
    6: "Microsoft",
    117: "Samsung",
    224: "Google",
    87: "Garmin",
    89: "Nordic Semi",
    269: "Sony",
    19: "Fitbit",
    157: "Huami (Xiaomi)",
    343: "Logitech",
    26: "Intel",
    8: "Motorola",
    1: "Nokia",
    16: "Toshiba",
    72: "Misfit",
    196: "Bose",
}

# BLE Appearance Values (Category)
APPEARANCE_MAP = {
    0: "Unknown",
    64: "Phone 📱",
    128: "Computer 💻",
    192: "Watch ⌚",
    193: "Sport Watch ⌚",
    832: "Heart Rate ❤️",
    833: "Heart Rate ❤️",
    960: "Keyboard ⌨️",
    961: "Mouse 🖱️",
    962: "Joystick 🎮",
    1088: "Speaker 🔊",
    1089: "Headphones 🎧",
    3264: "Co2 Sensor 🌫️"
}

async def inspect_device(mac_address):
    print(f"[BLE AGENT] Inspecting {mac_address}...")
    result = {"mac": mac_address, "status": "failed", "details": {}}
    
    try:
        async with BleakClient(mac_address, timeout=12.0) as client:
            if client.is_connected:
                print(f"[BLE AGENT] Connected to {mac_address}")
                result["status"] = "connected"
                
                # Helper to safe read
                async def safe_read(uuid):
                    try:
                        return (await client.read_gatt_char(uuid)).decode('utf-8').strip()
                    except:
                        return None

                async def safe_read_bytes(uuid):
                    try:
                        return await client.read_gatt_char(uuid)
                    except:
                        return None
                
                # Standard Device Info Service (0x180A)
                result["details"]["manufacturer"] = await safe_read("00002a29-0000-1000-8000-00805f9b34fb")
                result["details"]["model"] = await safe_read("00002a24-0000-1000-8000-00805f9b34fb")
                result["details"]["serial"] = await safe_read("00002a25-0000-1000-8000-00805f9b34fb")
                
                # Battery Level (0x2A19)
                bat = await safe_read_bytes("00002a19-0000-1000-8000-00805f9b34fb")
                result["details"]["battery"] = int(bat[0]) if bat else None

                # Appearance (0x2A01) - Device Type
                app_bytes = await safe_read_bytes("00002a01-0000-1000-8000-00805f9b34fb")
                if app_bytes:
                    val = int.from_bytes(app_bytes, byteorder='little')
                    cat = APPEARANCE_MAP.get(val & 0xFFC0, None) or APPEARANCE_MAP.get(val, "Unknown Device")
                    result["details"]["type"] = cat
                else:
                    result["details"]["type"] = None

                # Additional device info
                result["details"]["firmware"] = await safe_read("00002a26-0000-1000-8000-00805f9b34fb")  # Firmware Revision
                result["details"]["hardware"] = await safe_read("00002a27-0000-1000-8000-00805f9b34fb")  # Hardware Revision
                result["details"]["software"] = await safe_read("00002a28-0000-1000-8000-00805f9b34fb")  # Software Revision

                # GATT Services Discovery
                services_info = []
                try:
                    for service in client.services:
                        service_data = {
                            "uuid": service.uuid,
                            "description": service.description or "Unknown Service",
                            "characteristics": []
                        }

                        # List characteristics for each service
                        for char in service.characteristics:
                            char_data = {
                                "uuid": char.uuid,
                                "description": char.description or "Unknown",
                                "properties": char.properties
                            }
                            service_data["characteristics"].append(char_data)

                        services_info.append(service_data)

                    result["details"]["services"] = services_info
                    result["details"]["service_count"] = len(services_info)
                except Exception as e:
                    result["details"]["services"] = []
                    result["details"]["service_count"] = 0

                # Connection info
                try:
                    result["details"]["mtu"] = client.mtu_size if hasattr(client, 'mtu_size') else None
                    result["details"]["is_connected"] = client.is_connected
                except:
                    pass

            else:
                 print(f"[BLE AGENT] Failed to connect to {mac_address}")
                 result["details"]["error"] = "Connection Timeout"

    except Exception as e:
         print(f"[BLE AGENT] Inspection Error: {e}")
         result["details"]["error"] = str(e)

    # Post Result
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(f"{BACKEND_URL}/ble/inspection_result", json=result)
            print(f"[BLE AGENT] Inspection result sent for {mac_address}")
    except:
        pass

async def main():
    print("[BLE AGENT] Starting... (Running as User)")
    scanning = False
    
    # Device Cache: {mac: {"device": dev, "adv": adv, "last_seen": timestamp}}
    device_cache = {}
    
    while True:
        try:
            # 1. Check if we should be scanning OR Inspecting
            should_scan = False
            target_mac = None
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{BACKEND_URL}/ble/status") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        should_scan = data.get("scanning", False)
                        target_mac = data.get("inspection_target", None)
                        
                        # Handle Reset Signal
                        if data.get("reset_signal", False):
                            print("[BLE AGENT] Received RESET Signal. Clearing Cache.")
                            device_cache.clear()
                            
        except Exception as e:
            # Backend might be down or starting up
            # print(f"[BLE AGENT] Backend unavailable: {e}") # Too verbose
            # print(".", end="", flush=True) # Simple heartbeat
            await asyncio.sleep(2)
            continue

        # PRIORITY: Inspection
        if target_mac:
             print(f"[BLE AGENT] PAUSING SCAN for Inspection of {target_mac}")
             scanning = False # Temporarily stop scanning
             await inspect_device(target_mac)
             await asyncio.sleep(2) # Cooldown
             continue

        if should_scan:
            if not scanning:
                print("[BLE AGENT] Scanning ENABLED")
                scanning = True
            
            # Temporary buffer for valid callbacks
            # We update the main cache directly in callback
            
            def callback(device, advertisement_data):
                nonlocal device_cache
                device_cache[device.address] = {
                    "device": device,
                    "adv": advertisement_data,
                    "last_seen": time.time()
                }

            try:
                # Scan for 2 seconds
                async with BleakScanner(detection_callback=callback) as scanner:
                    await asyncio.sleep(2.0)
                
                # Prune old devices (> 10s) and Format data
                current_time = time.time()
                results = []
                expired_macs = []
                
                for mac, info in device_cache.items():
                    if current_time - info["last_seen"] > 10.0:
                        expired_macs.append(mac)
                        continue
                    
                    d = info["device"]
                    adv = info["adv"]
                    
                    # Manufacturer parsing
                    ble_vendor = "Unknown"
                    manu_data = adv.manufacturer_data

                    # Check known BLE vendor IDs
                    for vid, name in VENDOR_IDS.items():
                        if vid in manu_data:
                            ble_vendor = name
                            break

                    # If local name suggests something
                    if ble_vendor == "Unknown" and d.name:
                        if "iPhone" in d.name: ble_vendor = "Apple"
                        elif "TV" in d.name: ble_vendor = "Smart TV"

                    # Get OUI-based vendor from MAC address
                    oui_vendor = lookup_mac_vendor(d.address)

                    # Prefer BLE manufacturer data, fallback to OUI lookup
                    final_vendor = ble_vendor if ble_vendor != "Unknown" else oui_vendor

                    # Update proximity manager
                    proximity_manager.update_device(d.address, adv.rssi, final_vendor)

                    # Get distance estimate
                    distance = proximity_manager.get_smoothed_distance(d.address)
                    device_info = proximity_manager.get_device_info(d.address)

                    results.append({
                        "mac": d.address,
                        "name": d.name or "Unknown",
                        "rssi": adv.rssi,
                        "vendor": final_vendor,
                        "oui_vendor": oui_vendor,  # Include OUI vendor for reference
                        "ble_vendor": ble_vendor,   # Include BLE vendor for reference
                        "distance": distance,  # NEW: Distance estimate
                        "is_random_mac": device_info["is_random_mac"] if device_info else False,  # NEW: Random MAC detection
                        "random_mac_confidence": device_info["random_mac_confidence"] if device_info else 0.0  # NEW
                    })
                
                # Cleanup expired
                for mac in expired_macs:
                    del device_cache[mac]
                
                # Post results to backend
                if results:
                    async with aiohttp.ClientSession() as session:
                        await session.post(f"{BACKEND_URL}/ble/results", json=results)
                        
            except Exception as e:
                print(f"[BLE AGENT] Scan error: {e}")
        
        else:
            if scanning:
                print("[BLE AGENT] Scanning PAUSED")
                scanning = False
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        import time # Ensure time is imported
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
