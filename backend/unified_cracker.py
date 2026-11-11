"""
Unified Cracker Module for ARCH // HUNTER
Consolidates handshake and PMKID cracking into a single interface.
Uses aircrack-ng for both, with progress parsing.
"""
import subprocess
import os
import re
import json
import time
import shutil

CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "captures")
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "crack_history.json")
TMP_AIRCRACK_CAP = "/tmp/unified_crack_pmkid.cap"


class UnifiedCracker:
    def __init__(self):
        self.process = None
        self.cracking = False
        self.current_target = None  # {"bssid", "ssid", "source_type"}
        self.progress = {
            "keys_tested": 0,
            "total_keys": 0,
            "keys_per_sec": 0.0,
            "elapsed": "00:00:00",
            "percentage": 0.0
        }
        self.history = []
        self._load_history()

    def _get_aircrack_path(self):
        for path in ["/usr/bin/aircrack-ng", "/usr/local/bin/aircrack-ng", "/opt/homebrew/bin/aircrack-ng"]:
            if os.path.exists(path):
                return path
        return shutil.which("aircrack-ng") or "aircrack-ng"

    def _find_tool(self, name):
        for path in [f"/usr/bin/{name}", f"/usr/sbin/{name}", f"/usr/local/bin/{name}"]:
            if os.path.exists(path):
                return path
        return shutil.which(name) or name

    def _strip_ansi(self, text):
        return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

    def _parse_progress(self, line):
        """Parse aircrack-ng progress lines.
        Format: [00:00:01] 1234/10000 keys tested (1234.00 k/s)
        """
        match = re.search(
            r'\[(\d{2}:\d{2}:\d{2})\]\s+(\d+)/(\d+)\s+keys tested\s+\(([0-9.]+)\s+k/s\)',
            line
        )
        if match:
            keys_tested = int(match.group(2))
            total_keys = int(match.group(3))
            self.progress = {
                "elapsed": match.group(1),
                "keys_tested": keys_tested,
                "total_keys": total_keys,
                "keys_per_sec": float(match.group(4)),
                "percentage": round(keys_tested / max(total_keys, 1) * 100, 1)
            }
            return True
        return False

    def _resolve_capture_file(self, bssid, source_type):
        """Find the capture file for cracking based on source type."""
        sanitized = bssid.replace(":", "-")

        if source_type == "auto":
            # Priority 1: handshake pcap
            hs_file = os.path.join(CAPTURE_DIR, f"handshake_{sanitized}.pcap")
            if os.path.exists(hs_file):
                return hs_file, "handshake"
            # Priority 2: PMKID .22000
            pmkid_file = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.22000")
            if os.path.exists(pmkid_file):
                return pmkid_file, "pmkid"
            # Priority 3: PMKID pcap (legacy)
            pmkid_pcap = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.pcap")
            if os.path.exists(pmkid_pcap):
                return pmkid_pcap, "handshake"
            return None, None

        elif source_type == "handshake":
            hs_file = os.path.join(CAPTURE_DIR, f"handshake_{sanitized}.pcap")
            if os.path.exists(hs_file):
                return hs_file, "handshake"
            return None, None

        elif source_type == "pmkid":
            pmkid_file = os.path.join(CAPTURE_DIR, f"pmkid_{sanitized}.22000")
            if os.path.exists(pmkid_file):
                return pmkid_file, "pmkid"
            return None, None

        return None, None

    def _convert_pmkid_for_aircrack(self, hash_file_22000, callback=None):
        """Convert .22000 file to aircrack-ng compatible cap format using hcxhash2cap."""
        hcxhash2cap = self._find_tool("hcxhash2cap")

        # Clean old file
        try:
            os.remove(TMP_AIRCRACK_CAP)
        except FileNotFoundError:
            pass

        cmd = [hcxhash2cap, f"--pmkid-eapol={hash_file_22000}", "-c", TMP_AIRCRACK_CAP]
        if callback:
            callback(f"Converting PMKID hash: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if not os.path.exists(TMP_AIRCRACK_CAP):
            raise RuntimeError(f"hcxhash2cap failed: {result.stderr.strip()}")

        if callback:
            callback("Conversion complete.")
        return TMP_AIRCRACK_CAP

    def crack(self, bssid, ssid, wordlist, source_type="auto", status_callback=None, progress_callback=None):
        """Unified crack entry point.

        Args:
            bssid: Target BSSID
            ssid: Target SSID
            wordlist: Path to wordlist file
            source_type: "auto", "handshake", or "pmkid"
            status_callback: Function to receive log messages
            progress_callback: Function to receive progress updates
        """
        if self.cracking:
            return {"status": "error", "msg": "Already cracking"}

        self.cracking = True
        self.current_target = {"bssid": bssid, "ssid": ssid, "source_type": source_type}
        self.progress = {
            "keys_tested": 0, "total_keys": 0,
            "keys_per_sec": 0.0, "elapsed": "00:00:00", "percentage": 0.0
        }

        start_time = time.time()

        try:
            # Validate wordlist
            if not os.path.exists(wordlist):
                if status_callback:
                    status_callback(f"ERROR: Wordlist not found: {wordlist}")
                return {"status": "error", "msg": "Wordlist not found"}

            # Resolve capture file
            capture_file, resolved_type = self._resolve_capture_file(bssid, source_type)
            if not capture_file:
                if status_callback:
                    status_callback(f"ERROR: No capture file found for {bssid} (source: {source_type})")
                return {"status": "error", "msg": "No capture file found"}

            # Update source type to what was actually resolved
            self.current_target["source_type"] = resolved_type
            if status_callback:
                status_callback(f"Source: {resolved_type.upper()} | File: {os.path.basename(capture_file)}")

            # For PMKID: convert .22000 → cap
            if resolved_type == "pmkid":
                try:
                    capture_file = self._convert_pmkid_for_aircrack(capture_file, status_callback)
                except Exception as e:
                    if status_callback:
                        status_callback(f"ERROR: PMKID conversion failed: {e}")
                    return {"status": "error", "msg": f"PMKID conversion failed: {e}"}

            # Run aircrack-ng
            aircrack_bin = self._get_aircrack_path()
            cmd = [aircrack_bin, "-w", wordlist, "-e", ssid, capture_file]
            if status_callback:
                status_callback(f"CMD: {' '.join(cmd)}")

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            key_found = False
            found_key = None
            last_progress_time = 0

            for line in iter(self.process.stdout.readline, ''):
                if not line:
                    break

                clean_line = self._strip_ansi(line).strip()
                if not clean_line:
                    continue

                # Log line
                if status_callback:
                    status_callback(clean_line)

                # Parse progress
                if self._parse_progress(clean_line):
                    now = time.time()
                    if now - last_progress_time >= 0.5 and progress_callback:
                        progress_callback(self.progress)
                        last_progress_time = now

                # Check for key
                if "KEY FOUND!" in clean_line:
                    match = re.search(r'KEY FOUND!\s*\[\s*(.*?)\s*\]', clean_line)
                    if match:
                        found_key = match.group(1)
                        key_found = True

            self.process.wait()
            self.process = None

            elapsed = int(time.time() - start_time)

            if key_found:
                result = {"status": "success", "key": found_key}
            else:
                result = {"status": "failed", "msg": "Password not found"}

            # Add to history
            self._add_to_history({
                "bssid": bssid,
                "ssid": ssid,
                "source_type": resolved_type,
                "status": result["status"],
                "key": result.get("key"),
                "timestamp": time.time(),
                "elapsed_seconds": elapsed,
                "progress": self.progress.copy()
            })

            return result

        except FileNotFoundError:
            if status_callback:
                status_callback("CRITICAL: aircrack-ng binary not found")
            return {"status": "error", "msg": "aircrack-ng not found on system"}
        except Exception as e:
            if status_callback:
                status_callback(f"ERROR: {e}")
            return {"status": "error", "msg": str(e)}
        finally:
            self.cracking = False
            self.process = None

    def stop(self):
        """Stop active crack process."""
        if not self.cracking and not self.process:
            return False

        self.cracking = False

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

        # Add stopped entry to history
        if self.current_target:
            self._add_to_history({
                "bssid": self.current_target.get("bssid", ""),
                "ssid": self.current_target.get("ssid", ""),
                "source_type": self.current_target.get("source_type", ""),
                "status": "stopped",
                "key": None,
                "timestamp": time.time(),
                "elapsed_seconds": 0,
                "progress": self.progress.copy()
            })

        self.current_target = None
        return True

    def get_progress(self):
        """Return current progress dict."""
        return self.progress.copy()

    def get_status(self):
        """Return full cracker status for WebSocket."""
        return {
            "cracking": self.cracking,
            "target": self.current_target,
            "progress": self.progress.copy()
        }

    def get_history(self):
        """Return crack history list."""
        return list(self.history)

    def get_targets(self):
        """List all crackable targets from capture files."""
        targets = []
        if not os.path.exists(CAPTURE_DIR):
            return targets

        seen = set()
        for f in os.listdir(CAPTURE_DIR):
            if f.startswith("handshake_") and f.endswith(".pcap"):
                bssid = f.replace("handshake_", "").replace(".pcap", "").replace("-", ":")
                if bssid not in seen:
                    seen.add(bssid)
                    targets.append({
                        "bssid": bssid,
                        "source": "handshake",
                        "file": f,
                        "size": os.path.getsize(os.path.join(CAPTURE_DIR, f))
                    })
            elif f.startswith("pmkid_") and f.endswith(".22000"):
                bssid = f.replace("pmkid_", "").replace(".22000", "").replace("-", ":")
                if bssid not in seen:
                    seen.add(bssid)
                    targets.append({
                        "bssid": bssid,
                        "source": "pmkid",
                        "file": f,
                        "size": os.path.getsize(os.path.join(CAPTURE_DIR, f))
                    })

        return targets

    def _add_to_history(self, entry):
        """Add completed crack to history. Keeps last 50."""
        self.history.append(entry)
        if len(self.history) > 50:
            self.history = self.history[-50:]
        self._save_history()

    def _save_history(self):
        """Persist history to JSON file."""
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"[CRACK] Failed to save history: {e}")

    def _load_history(self):
        """Load history from JSON file."""
        try:
            with open(HISTORY_FILE, "r") as f:
                self.history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.history = []
