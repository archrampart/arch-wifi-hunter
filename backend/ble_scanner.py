import asyncio
from bleak import BleakScanner
import time
from backend.oui_lookup import lookup_mac_vendor

# ===================================================================================
# 🔒 BLE SCANNER CLASS - LOCKED 🔒
# ===================================================================================
# See ble_agent.py for the active agent implementation.
# ===================================================================================

class BLEScanner:
    def __init__(self):
        self.devices = {} # mac -> {name, rssi, manufacturer, last_seen}
        self.scanner = None
        self.scanning = False

    async def start_scan(self):
        if self.scanning:
            return

        self.scanning = True
        print("Starting BLE Scan...")
        
        def callback(device, advertisement_data):
            # Parse Manufacturer Data
            # Apple is ID 76 (0x004c)
            # Microsoft is ID 6 (0x0006)
            ble_vendor = "Unknown"
            manu_data = advertisement_data.manufacturer_data

            if 76 in manu_data:
                ble_vendor = "Apple"
            elif 6 in manu_data:
                ble_vendor = "Microsoft"
            elif 117 in manu_data:
                ble_vendor = "Samsung"
            elif 224 in manu_data:
                ble_vendor = "Google"

            # Get OUI-based vendor from MAC address
            oui_vendor = lookup_mac_vendor(device.address)

            # Prefer BLE manufacturer data, fallback to OUI lookup
            final_vendor = ble_vendor if ble_vendor != "Unknown" else oui_vendor

            # Update device list
            self.devices[device.address] = {
                "mac": device.address,
                "name": device.name or "Unknown Device",
                "rssi": device.rssi,
                "vendor": final_vendor,
                "oui_vendor": oui_vendor,  # Always include OUI vendor for reference
                "ble_vendor": ble_vendor,  # BLE manufacturer data vendor
                "last_seen": time.time(),
                "raw_manu": str(manu_data) if manu_data else ""
            }

        self.scanner = BleakScanner(detection_callback=callback)
        await self.scanner.start()
        
        # Scan indefinitely until stopped
        try:
            while self.scanning:
                await asyncio.sleep(1)
                # Cleanup old devices (optional, maybe keep them for history)
                # For now we keep everything
        except asyncio.CancelledError:
            pass
        finally:
            await self.scanner.stop()
            print("BLE Scan Stopped")

    async def stop_scan(self):
        self.scanning = False
        if self.scanner:
             await self.scanner.stop()

    def get_devices(self):
        # Return list of devices sorted by signal strength
        return sorted(self.devices.values(), key=lambda x: x['rssi'], reverse=True)
