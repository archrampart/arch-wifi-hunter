import subprocess
import re
import shutil
import os
from backend.oui_lookup import lookup_mac_vendor
from backend.platform_wifi import IS_MACOS, IS_LINUX, AIRPORT_PATH

class SafeScanner:
    def __init__(self, interface="en0"):
        self.interface = interface

    def scan(self):
        """
        Runs platform-specific WiFi scan.
        macOS: airport -s
        Linux: iw dev <iface> scan
        Returns a list of dicts consistent with the existing network structure.
        """
        if IS_MACOS:
            return self._scan_macos()
        else:
            return self._scan_linux()

    def _scan_macos(self):
        """Scan using macOS airport utility."""
        if not os.path.exists(AIRPORT_PATH):
            return []

        try:
            cmd = [AIRPORT_PATH, self.interface, "-s"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                print(f"Scan Error: {result.stderr}")
                return []

            return self._parse_output(result.stdout)
        except Exception as e:
            print(f"Safe scan failed: {e}")
            return []

    def _scan_linux(self):
        """Scan using nmcli on Linux (avoids NetworkManager device-busy conflict)."""
        try:
            # Check if interface is in AP mode (Evil Twin active) — skip scan
            r = subprocess.run(["iw", "dev", self.interface, "info"],
                               capture_output=True, text=True, timeout=5)
            if "type AP" in r.stdout:
                return []

            # Ensure NetworkManager is running (needed for nmcli)
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                capture_output=True, timeout=10
            )

            import time
            time.sleep(1)

            # Trigger a fresh scan (ignore errors - rescan can fail if busy)
            subprocess.run(
                ["nmcli", "dev", "wifi", "rescan"],
                capture_output=True, timeout=10
            )
            time.sleep(2)

            # Get results in machine-readable format
            cmd = [
                "nmcli", "-t", "-f",
                "BSSID,SSID,CHAN,SIGNAL,SECURITY",
                "dev", "wifi", "list"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            print(f"[DEBUG] nmcli returncode={result.returncode} stdout_len={len(result.stdout)} stderr={result.stderr.strip()}")

            if result.returncode == 0 and result.stdout.strip():
                networks = self._parse_nmcli_output(result.stdout)
                print(f"[+] nmcli scan found {len(networks)} networks")
                return networks

            # Fallback: iw dev scan (requires killing NetworkManager)
            # Re-check interface mode before destructive fallback
            r2 = subprocess.run(["iw", "dev", self.interface, "info"],
                                capture_output=True, text=True, timeout=5)
            if "type AP" in r2.stdout:
                print("[!] Interface in AP mode — skipping iw scan fallback")
                return []
            if "type monitor" in r2.stdout:
                print("[!] Interface in monitor mode — skipping iw scan fallback")
                return []

            print("[!] nmcli returned empty, falling back to iw scan...")
            subprocess.run(["airmon-ng", "check", "kill"],
                           capture_output=True, timeout=10)
            time.sleep(1)

            cmd = ["iw", "dev", self.interface, "scan"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                networks = self._parse_iw_output(result.stdout)
                subprocess.run(["systemctl", "start", "NetworkManager"],
                               capture_output=True, timeout=10)
                return networks

            print(f"Linux scan failed: {result.stderr}")
            subprocess.run(["systemctl", "start", "NetworkManager"],
                           capture_output=True, timeout=10)
            return []
        except Exception as e:
            print(f"Linux scan failed: {e}")
            return []

    def _parse_output(self, output):
        networks = []
        lines = output.strip().split('\n')
        if len(lines) < 2:
            return []

        # Headers typically: SSID BSSID RSSI CHANNEL HT CC SECURITY (RSSI)
        # But fixed width parsing is safer or regex.
        # Example output:
        # SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
        # MyWifi 00:11:22:33:44:55 -80  1      Y  US WPA2(PSK/AES/AES) 
        
        # Regex to capture content. SSID can have spaces.
        # However, airport -s columns are somewhat aligned.
        
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
                
            # Parsing from right to left is easier for details
            # Last part is Security? No, Security can be multiple parts "WPA2(PSK/AES/AES)"
            # Let's try to extract BSSID (format XX:XX:XX:XX:XX:XX)
            
            bssid_matches = re.findall(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
            if not bssid_matches:
                continue
            bssid = bssid_matches[0]
            
            # Split line by BSSID
            pre_bssid, post_bssid = line.split(bssid, 1)
            ssid = pre_bssid.strip()

            # Clean up SSID: remove non-printable characters and limit length
            ssid = ''.join(char for char in ssid if char.isprintable())
            if not ssid:
                ssid = "<HIDDEN>"
            
            # Parse post-BSSID: RSSI CHANNEL ...
            # Clean up extra spaces
            rest = post_bssid.strip().split()
            # rest[0] = RSSI, rest[1] = CHANNEL
            if len(rest) < 2:
                continue
            
            try:
                rssi = int(rest[0])
                channel = int(rest[1].split(',')[0]) # Sometimes "1,+1"
            except:
                continue
                
            # Security detection
            security_str = " ".join(rest[2:])
            wps = False 
            # Airport doesn't explicitly show WPS usually, but we can't detect it easily passively without monitor frames.
            # We'll default to False.
            
            # Get vendor from MAC address OUI
            vendor = lookup_mac_vendor(bssid)

            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "signal": rssi,
                "wps": wps,
                "vendor": vendor,  # Add vendor information
                "clients": {}, # Can't see clients in passive mode
                "is_evil_twin": False, # Will be detected below
                "pwned": False,
                "has_pmkid": False,
                "band": "5GHz" if channel > 14 else "2.4GHz"
            })

        return self._detect_evil_twins(networks)

    @staticmethod
    def _decode_nmcli_ssid(ssid):
        """Decode nmcli -t escaped SSID strings.
        nmcli -t mode escapes non-ASCII bytes as \\xNN sequences.
        Example: 'Y\\xC3\\xBCkseltici' -> 'Yükseltici'
        """
        if '\\x' not in ssid and '\\X' not in ssid:
            return ssid
        # Replace \\xNN sequences with actual bytes, then decode as UTF-8
        def replace_hex(m):
            return bytes([int(m.group(1), 16)])
        try:
            raw = re.sub(rb'\\[xX]([0-9A-Fa-f]{2})', replace_hex, ssid.encode('latin-1'))
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return ssid

    def _parse_nmcli_output(self, output):
        """Parse output of 'nmcli -t -f BSSID,SSID,CHAN,SIGNAL,SECURITY dev wifi list'."""
        networks = []
        seen_bssids = {}  # BSSID -> index in networks (for deduplication)

        for line in output.strip().split('\n'):
            if not line.strip():
                continue

            # nmcli -t uses ':' as delimiter, but BSSID contains ':'
            # BSSID is XX\:XX\:XX\:XX\:XX\:XX (escaped colons in -t mode)
            # Split by unescaped ':'
            parts = re.split(r'(?<!\\):', line)
            if len(parts) < 5:
                continue

            # Reconstruct BSSID (first 6 parts, unescape backslashes)
            bssid = ':'.join(parts[0:6]).replace('\\', '')
            ssid = parts[6] if len(parts) > 6 else "<HIDDEN>"
            if not ssid or ssid == "--":
                ssid = "<HIDDEN>"
            else:
                # Decode nmcli escaped non-ASCII characters (\xNN -> actual UTF-8)
                ssid = self._decode_nmcli_ssid(ssid)

            try:
                channel = int(parts[7]) if len(parts) > 7 else 0
            except (ValueError, IndexError):
                channel = 0

            try:
                # nmcli SIGNAL is 0-100 percentage, convert to approximate dBm
                signal_pct = int(parts[8]) if len(parts) > 8 else 0
                signal = int(-100 + signal_pct * 0.6)  # rough conversion
            except (ValueError, IndexError):
                signal = -100

            # Deduplicate: keep the entry with stronger signal for same BSSID
            bssid_lower = bssid.lower()
            if bssid_lower in seen_bssids:
                existing_idx = seen_bssids[bssid_lower]
                if signal > networks[existing_idx]["signal"]:
                    networks[existing_idx]["signal"] = signal
                    networks[existing_idx]["ssid"] = ssid
                    # Only update channel if new value is valid (non-zero)
                    if channel > 0:
                        networks[existing_idx]["channel"] = channel
                continue

            vendor = lookup_mac_vendor(bssid)

            seen_bssids[bssid_lower] = len(networks)
            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "signal": signal,
                "wps": False,
                "vendor": vendor,
                "clients": {},
                "is_evil_twin": False,
                "pwned": False,
                "has_pmkid": False,
                "band": "5GHz" if channel > 14 else "2.4GHz"
            })

        return self._detect_evil_twins(networks)

    def _parse_iw_output(self, output):
        """Parse output of 'iw dev <iface> scan'."""
        networks = []
        current = None

        for line in output.split('\n'):
            line = line.strip()

            # New BSS entry
            if line.startswith("BSS "):
                if current:
                    networks.append(current)
                bssid_match = re.match(r'BSS ([0-9a-f:]{17})', line)
                if bssid_match:
                    current = {
                        "ssid": "<HIDDEN>",
                        "bssid": bssid_match.group(1),
                        "channel": 0,
                        "signal": -100,
                        "wps": False,
                        "vendor": "",
                        "clients": {},
                        "is_evil_twin": False,
                        "pwned": False,
                        "has_pmkid": False,
                        "band": "2.4GHz"
                    }
                continue

            if not current:
                continue

            if line.startswith("SSID:"):
                ssid = line.split("SSID:", 1)[1].strip()
                if ssid:
                    current["ssid"] = ssid

            elif line.startswith("signal:"):
                try:
                    sig = float(line.split("signal:", 1)[1].strip().split()[0])
                    current["signal"] = int(sig)
                except (ValueError, IndexError):
                    pass

            elif line.startswith("DS Parameter set: channel"):
                try:
                    ch = int(line.split("channel")[1].strip())
                    current["channel"] = ch
                    current["band"] = "5GHz" if ch > 14 else "2.4GHz"
                except (ValueError, IndexError):
                    pass

            elif "* primary channel:" in line:
                try:
                    ch = int(line.split(":")[-1].strip())
                    current["channel"] = ch
                    current["band"] = "5GHz" if ch > 14 else "2.4GHz"
                except (ValueError, IndexError):
                    pass

            elif "WPS:" in line:
                current["wps"] = True

        # Don't forget the last entry
        if current:
            networks.append(current)

        # Add vendor info
        for net in networks:
            net["vendor"] = lookup_mac_vendor(net["bssid"])

        return self._detect_evil_twins(networks)

    def _parse_iwlist_output(self, output):
        """Parse output of 'iwlist <iface> scan' (fallback)."""
        networks = []
        current = None

        for line in output.split('\n'):
            line = line.strip()

            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(current)
                bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
                if bssid_match:
                    current = {
                        "ssid": "<HIDDEN>",
                        "bssid": bssid_match.group(1).lower(),
                        "channel": 0,
                        "signal": -100,
                        "wps": False,
                        "vendor": "",
                        "clients": {},
                        "is_evil_twin": False,
                        "pwned": False,
                        "has_pmkid": False,
                        "band": "2.4GHz"
                    }
                continue

            if not current:
                continue

            if "ESSID:" in line:
                match = re.search(r'ESSID:"(.+)"', line)
                if match:
                    current["ssid"] = match.group(1)

            elif "Channel:" in line:
                try:
                    ch = int(line.split("Channel:")[1].strip())
                    current["channel"] = ch
                    current["band"] = "5GHz" if ch > 14 else "2.4GHz"
                except (ValueError, IndexError):
                    pass

            elif "Signal level=" in line:
                try:
                    sig = int(re.search(r'Signal level=(-?\d+)', line).group(1))
                    current["signal"] = sig
                except (ValueError, AttributeError):
                    pass

        if current:
            networks.append(current)

        for net in networks:
            net["vendor"] = lookup_mac_vendor(net["bssid"])

        return self._detect_evil_twins(networks)

    @staticmethod
    def _detect_evil_twins(networks):
        """Detect evil twins: same SSID with different BSSIDs."""
        ssid_map = {}
        for net in networks:
            if net["ssid"] not in ssid_map:
                ssid_map[net["ssid"]] = []
            ssid_map[net["ssid"]].append(net)

        for ssid, nets in ssid_map.items():
            if len(nets) > 1 and ssid != "<HIDDEN>":
                for net in nets:
                    net["is_evil_twin"] = True

        return networks
