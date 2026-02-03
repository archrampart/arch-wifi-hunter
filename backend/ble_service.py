import asyncio
import time
from bleak import BleakScanner, BleakClient

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
    157: "Huami",
    343: "Logitech",
    26: "Intel",
}

class BLEService:
    def __init__(self, state_dict):
        """
        state_dict: A dictionary shared with main.py to store results.
        Keys: 'scanning', 'devices', 'inspection_target', 'inspection_result'
        """
        self.state = state_dict
        self.device_cache = {}
        self.scanner = None

    async def start_scan(self):
        self.state["scanning"] = True
        print("[BLE] Scan Started")

    async def stop_scan(self):
        self.state["scanning"] = False
        print("[BLE] Scan Stopped")

    async def inspect(self, mac):
        self.state["inspection_target"] = mac
        print(f"[BLE] Queued inspection for {mac}")

    async def _inspect_device(self, mac):
        print(f"[BLE] Inspecting {mac}...")
        result = {"mac": mac, "status": "failed", "details": {}}
        
        try:
            async with BleakClient(mac, timeout=12.0) as client:
                if client.is_connected:
                    result["status"] = "connected"
                    
                    # Helper to safe read
                    async def safe_read_str(uuid):
                        try:
                            return (await client.read_gatt_char(uuid)).decode('utf-8').strip()
                        except:
                            return None

                    async def safe_read_bytes(uuid):
                        try:
                            return await client.read_gatt_char(uuid)
                        except:
                            return None
                    
                    # Device Info Service
                    result["details"]["manufacturer"] = await safe_read_str("00002a29-0000-1000-8000-00805f9b34fb")
                    result["details"]["model"] = await safe_read_str("00002a24-0000-1000-8000-00805f9b34fb")
                    result["details"]["serial"] = await safe_read_str("00002a25-0000-1000-8000-00805f9b34fb")
                    
                    # Battery
                    bat = await safe_read_bytes("00002a19-0000-1000-8000-00805f9b34fb")
                    result["details"]["battery"] = int(bat[0]) if bat else None

                    # Use Vendor IDs fallback if Manufacturer string is empty
                    if not result["details"]["manufacturer"]:
                         # Try to guess
                         pass

        except Exception as e:
            print(f"[BLE] Inspection Error: {e}")
            result["details"]["error"] = str(e)
            
        self.state["inspection_result"] = result
        self.state["inspection_target"] = None # Clear target

    async def run_loop(self):
        """Main Background Loop"""
        print("[BLE] Service Loop Running")
        while True:
            try:
                # 1. Handle Inspection Priority
                target = self.state.get("inspection_target")
                if target:
                    # Pause scanning if active? BleakScanner acts independently usually, but better to pause.
                    was_scanning = self.state["scanning"]
                    if was_scanning:
                        # self.state["scanning"] = False # Logic handled in UI status
                        pass 
                    
                    await self._inspect_device(target)
                    await asyncio.sleep(1)
                    continue

                # 2. Handle Scanning
                if self.state["scanning"]:
                    # Define callback
                    def callback(device, advertisement_data):
                        self.device_cache[device.address] = {
                            "device": device,
                            "adv": advertisement_data,
                            "last_seen": time.time()
                        }

                    # Scan for short duration
                    async with BleakScanner(detection_callback=callback):
                        await asyncio.sleep(2.0)
                    
                    # Process Cache
                    current_time = time.time()
                    scan_results = []
                    expired = []

                    for mac, info in self.device_cache.items():
                        if current_time - info["last_seen"] > 10.0:
                            expired.append(mac)
                            continue
                        
                        d = info["device"]
                        adv = info["adv"]
                        vendor = "Unknown"
                        
                        # Vendor ID Check
                        if adv.manufacturer_data:
                            for vid in adv.manufacturer_data.keys():
                                if vid in VENDOR_IDS:
                                    vendor = VENDOR_IDS[vid]
                                    break
                        
                        # Name heuristics
                        name = d.name or "Unknown"
                        if vendor == "Unknown":
                            if "iPhone" in name: vendor = "Apple"
                            elif "TV" in name: vendor = "Smart TV"

                        scan_results.append({
                            "mac": mac,
                            "name": name,
                            "rssi": adv.rssi,
                            "vendor": vendor
                        })
                    
                    # Update State
                    self.state["devices"] = scan_results

                    # Prune
                    for mac in expired:
                        del self.device_cache[mac]
                
                else:
                    await asyncio.sleep(1)

            except Exception as e:
                print(f"[BLE] Loop Error: {e}")
                await asyncio.sleep(2)
