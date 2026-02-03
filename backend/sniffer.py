from scapy.all import *
import threading
import time
import subprocess
import os
import json
from backend.oui_lookup import lookup_mac_vendor
from backend.ble_proximity import proximity_manager
from backend.platform_wifi import IS_MACOS

# Scapy configuration
conf.use_pcap = True

# ===================================================================================
# CRITICAL: WIFI SCANNING LOGIC IS LOCKED. (STABLE CONFIGURATION - JAN 2026)
# DO NOT MODIFY PACKET CAPTURE/FILTERING LOGIC WITHOUT EXPLICIT "DOUBLE" USER APPROVAL.
# ===================================================================================

class PacketSniffer:
    def __init__(self, interface="en0"):
        self.interface = interface
        self.stop_event = threading.Event()
        self.access_points = {} # BSSID -> {ssid, channel, signal, encryption, clients: {mac: vendor}}
        self.beacon_cache = {} # BSSID -> Raw Packet
        self.handshakes = []
        self.process = None
        self.oui_db = self._load_oui()

        # NEW: Standalone WiFi clients tracking (independent of AP association)
        self.wifi_clients = {} # MAC -> {vendor, signal, last_seen, probes: [ssid1, ssid2], connected_to: bssid}

    def _load_oui(self):
        # Legacy method - now using oui_lookup module
        # Keep for backward compatibility but return empty dict
        return {}

    def _get_vendor(self, mac):
        """Get vendor name from MAC address using OUI lookup."""
        try:
            return lookup_mac_vendor(mac)
        except:
            return "Unknown"

    def start(self):
        """
        Starts the sniffing process by running tcpdump and reading its stdout.
        """
        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        print(f"Sniffer (Tcpdump Pipe) started on {self.interface}")

    def stop(self):
        """
        Stops the sniffing process.
        """
        self.stop_event.set()
        if self.process:
            try:
                self.process.kill() # FORCE KILL
                self.process.wait(timeout=1)
            except Exception as e:
                print(f"Error killing process: {e}")
            finally:
                self.process = None
        
        if hasattr(self, 'sniff_thread'):
            self.sniff_thread.join(timeout=2)
        print("Sniffer stopped.")

    def _sniff_loop(self):
        # Command: tcpdump -I -i en0 -w - -U
        # -I: Monitor mode
        # -w -: Write pcap to stdout
        # -U: Packet-buffered (immediate output)
        # macOS: -I flag puts interface into monitor mode
        # Linux: monitor mode is set externally via airmon-ng, no -I needed
        if IS_MACOS:
            cmd = ["tcpdump", "-I", "-i", self.interface, "-w", "-", "-U"]
        else:
            cmd = ["tcpdump", "-i", self.interface, "-w", "-", "-U"]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )

            # Use Scapy's PcapReader to read from the pipe
            # PcapReader accepts a file object
            with PcapReader(self.process.stdout) as pcap_reader:
                for packet in pcap_reader:
                    if self.stop_event.is_set():
                        break
                    try:
                        self._process_packet(packet)
                    except Exception as e:
                        # Parsing errors can happen with partial packets
                        pass

        except Exception as e:
            print(f"Sniffing error (Pipe): {e}")
        finally:
            if self.process:
                self.process.terminate()

    def _process_packet(self, packet):
        if packet.haslayer(Dot11Beacon):
            self._handle_beacon(packet)
        
        if packet.haslayer(EAPOL):
            self._handle_handshake(packet)

        # Client Fingerprinting: Probe Requests (Clients looking for networks)
        if packet.haslayer(Dot11ProbeReq):
            self._handle_probe(packet)

        # Client Fingerprinting: Data frames (Clients talking to APs)
        if packet.haslayer(Dot11) and packet.type == 2:
            self._handle_data(packet)

    def _handle_probe(self, packet):
        # Client scanning for networks (Probe Request)
        client_mac = packet.addr2
        if not client_mac:
            return

        # Filter out broadcast/multicast MACs
        if client_mac.lower().startswith('ff:ff:ff') or client_mac.lower().startswith('01:00:5e'):
            return

        # Extract SSID from probe request
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            # Broadcast probe (empty SSID)
            if not ssid:
                ssid = "<broadcast>"
        except:
            ssid = "<broadcast>"

        # DEBUG: Log probe detection
        print(f"[SNIFFER] Probe detected: {client_mac} -> {ssid}")

        # Get signal strength
        try:
            signal = packet.dBm_AntSignal
        except:
            signal = -100

        # Update or create client entry
        if client_mac not in self.wifi_clients:
            distance = proximity_manager.rssi_to_distance(signal)
            self.wifi_clients[client_mac] = {
                "vendor": self._get_vendor(client_mac),
                "signal": signal,
                "distance": round(distance, 2),
                "last_seen": time.time(),
                "probes": [],
                "connected_to": None
            }
            print(f"[SNIFFER] New client tracked: {client_mac}")

        # Update existing client
        client = self.wifi_clients[client_mac]
        client["signal"] = signal
        client["last_seen"] = time.time()

        # Calculate distance from RSSI (NEW)
        distance = proximity_manager.rssi_to_distance(signal)
        client["distance"] = round(distance, 2)

        # Add SSID to probe list if not broadcast and not already in list
        if ssid != "<broadcast>" and ssid not in client["probes"]:
            client["probes"].append(ssid)
            print(f"[SNIFFER] Added probe '{ssid}' to {client_mac}. Total probes: {len(client['probes'])}")
            # Limit to last 10 probes
            if len(client["probes"]) > 10:
                client["probes"] = client["probes"][-10:]

    def _handle_data(self, packet):
        # Determine direction to find BSSID and Client
        # ToDS=1, FromDS=0 -> Client sent to AP (addr1=BSSID, addr2=Client)
        # ToDS=0, FromDS=1 -> AP sent to Client (addr1=Client, addr2=BSSID)

        DS = packet.FCfield & 0x3
        to_ds = DS & 0x1 != 0
        from_ds = DS & 0x2 != 0

        bssid = None
        client_mac = None

        if to_ds and not from_ds:
            bssid = packet.addr1
            client_mac = packet.addr2
        elif not to_ds and from_ds:
            bssid = packet.addr2
            client_mac = packet.addr1

        if bssid and client_mac and bssid in self.access_points:
             # EXISTING: Add client to AP (DO NOT MODIFY)
             if "clients" not in self.access_points[bssid]:
                 self.access_points[bssid]["clients"] = {}

             if client_mac not in self.access_points[bssid]["clients"]:
                 vendor = self._get_vendor(client_mac)
                 self.access_points[bssid]["clients"][client_mac] = vendor

             # NEW: Also update standalone client tracking
             if client_mac:
                 # Get signal strength
                 try:
                     signal = packet.dBm_AntSignal
                 except:
                     signal = -100

                 # Update or create client entry
                 if client_mac not in self.wifi_clients:
                     distance = proximity_manager.rssi_to_distance(signal)
                     self.wifi_clients[client_mac] = {
                         "vendor": self._get_vendor(client_mac),
                         "signal": signal,
                         "distance": round(distance, 2),
                         "last_seen": time.time(),
                         "probes": [],
                         "connected_to": bssid
                     }
                     print(f"[SNIFFER] New client from data frame: {client_mac} -> AP: {bssid}")
                 else:
                     # Update existing client
                     client = self.wifi_clients[client_mac]
                     client["signal"] = signal
                     client["last_seen"] = time.time()
                     client["connected_to"] = bssid

                     # Calculate distance from RSSI (NEW)
                     distance = proximity_manager.rssi_to_distance(signal)
                     client["distance"] = round(distance, 2)

    def _handle_beacon(self, packet):
        bssid = packet[Dot11].addr3
        
        # Cache the raw beacon packet for cracking context
        self.beacon_cache[bssid] = packet
        
        try:
            # Decode SSID
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            # Filter empty SSIDs (hidden networks usually empty or null)
            if not ssid: 
                ssid = "<hidden>"
        except:
            ssid = "<hidden>"
            
        # Radiotap header is present in monitor mode, extracting dBm_AntSignal
        try:
            signal_strength = packet.dBm_AntSignal
        except:
            signal_strength = -100

        # Extract Channel (DS Parameter Set, ID=3) or HT Operation (ID=61)
        channel = 0
        wps_support = False
        try:
            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                # DS Parameter Set (ID=3) — primary channel for 2.4GHz
                if p.ID == 3 and p.info and len(p.info) >= 1:
                    ch = p.info[0] if isinstance(p.info[0], int) else ord(p.info[0])
                    if 1 <= ch <= 233:
                        channel = ch

                # HT Operation (ID=61) — primary channel (works for 5GHz too)
                if p.ID == 61 and p.info and len(p.info) >= 1 and channel == 0:
                    ch = p.info[0] if isinstance(p.info[0], int) else ord(p.info[0])
                    if 1 <= ch <= 233:
                        channel = ch

                # Check for WPS (Vendor Specific Tag 221, OUI 00:50:F2, Type 04)
                if p.ID == 221:
                    if p.info.startswith(b'\x00\x50\xf2\x04'):
                        wps_support = True

                p = p.payload
        except:
            pass

        # Fallback: try to get channel from Radiotap header
        if channel == 0:
            try:
                freq = packet[RadioTap].ChannelFrequency
                if freq:
                    if 2412 <= freq <= 2484:
                        channel = (freq - 2407) // 5
                        if freq == 2484:
                            channel = 14
                    elif 5170 <= freq <= 5825:
                        channel = (freq - 5000) // 5
            except:
                pass

        # Check for Evil Twins (Duplicate SSIDs with different BSSIDs)
        is_evil = False
        if ssid and ssid != "<hidden>":
            for other_bssid, other_data in self.access_points.items():
                if other_bssid != bssid:
                    if other_data.get('ssid') == ssid:
                        # FOUND DUPLICATE!
                        is_evil = True
                        # Also mark the other one
                        other_data['is_evil_twin'] = True
        
        # If channel is still 0 and we already have this AP with a valid channel, keep it
        if channel == 0 and bssid in self.access_points:
            channel = self.access_points[bssid].get("channel", 0)

        self.access_points[bssid] = {
            "ssid": ssid,
            "signal": signal_strength,
            "channel": channel,
            "wps": wps_support,
            "last_seen": time.time(),
            "is_evil_twin": is_evil
        }

    def _handle_handshake(self, packet):
        # EAPOL frames (Key exchange)
        bssid = packet.addr3
        
        # Check for PMKID (Usually in Message 1 of 4-way handshake)
        # RSN IE is Tag 48. Scapy parses this in Dot11Elt usually if attached to Beacon/Probe,
        # but in EAPOL Key frame, it's inside the Key Data field (if encrypted) or determined by context.
        # WAIT: PMKID is in the RSN IE of the Association Request usually? 
        # CORRECTION: PMKID is sent by the AP in the first EAPOL frame (Message 1) in the RSN IE (Key Data).
        # But commonly it is said to be in the "RSN Information Element" which might be appended.
        
        # Let's inspect the packet payload for PMKID signature (Tag 48, Len 20+, PMKID Count > 0)
        # WPA Key Data is often encrypted in msg 3, but in msg 1 it might be visible if RSN IE is present?
        # Actually PMKID attack relies on the RSN IE being present in the first EAPOL frame sent by AP.
        try:
            # EAPOL Detection Improvement
            is_eapol = False
            if packet.haslayer('EAPOL'):
                is_eapol = True
            elif packet.haslayer('Dot11') and packet.type == 2:
                # Check for LLC/SNAP: 8 bytes: AA AA 03 00 00 00 88 8E
                try:
                    if packet.haslayer(Dot11):
                         raw_payload = bytes(packet[Dot11].payload)
                         if b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' in raw_payload:
                             is_eapol = True
                except:
                    pass
        except:
             is_eapol = False

        try:
            if is_eapol:
                 # Basic check: Is it EAPOL Key?
                 # Check for PMKID in raw payload
                 load = bytes(packet) # Look in whole packet to be safe
                 if b'\x30\x14\x01\x00\x00\x0f\xac\x04' in load:
                     # ... (PMKID Logic) ...
                     pass # Already handled by inner check if we parse it, but for now we rely on simple match

                     
                     # RSN IE Signature: Element ID 48 (0x30)
                     # We look for sequence where 0x30 is followed by length, then OUI 00:0F:AC:04 (PMKID)
                     # Simple byte search for now
                     if b'\x30\x14\x01\x00\x00\x0f\xac\x04' in load:
                         # This is a very rough signature. 
                         # Better: use scapy to parse if possible, or robust byte extraction.
                         # Let's assume we capture the packet.
                         
                         print(f"PMKID Detected for {bssid}!")
                         # We save this as a separate "pmkid" capture
                         capture_dir = "backend/captures"
                         os.makedirs(capture_dir, exist_ok=True)
                         pmkid_filename = f"{capture_dir}/pmkid_{bssid.replace(':', '-')}.pcap"
                         wrpcap(pmkid_filename, packet, append=True)
                         
                         # Update Access Point to show PMKID Captured
                         if bssid in self.access_points:
                             self.access_points[bssid]['pmkid'] = True
        except Exception as e:
            print(f"PMKID check error: {e}")

        # Normal Handshake Logic (Existing)
        # We need a stable, writable path.
        capture_dir = "backend/captures"
        os.makedirs(capture_dir, exist_ok=True)
        
        filename = f"{capture_dir}/handshake_{bssid.replace(':', '-')}.pcap"
        
        try:
            packet_list = []
            
            # If file doesn't exist or is empty, we MUST inject the beacon frame first
            # aircrack-ng needs the Beacon to verify the SSID/ESSID.
            if not os.path.exists(filename) or os.path.getsize(filename) == 0:
                if bssid in self.beacon_cache:
                    packet_list.append(self.beacon_cache[bssid])
            
            packet_list.append(packet)
            
            # Append packet to this file
            wrpcap(filename, packet_list, append=True)
            print(f"Written EAPOL to {filename}")
            
            # Update our knowledge base
            exists = False
            for h in self.handshakes:
                if h["bssid"] == bssid:
                    h["time"] = int(time.time()) # Update last seen time
                    exists = True
                    break
            
            if not exists:
                self.handshakes.append({
                    "bssid": bssid,
                    "client": packet.addr1 if packet.addr1 != bssid else packet.addr2,
                    "file": filename,
                    "time": int(time.time())
                })
                
        except Exception as e:
            print(f"Error saving handshake: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root")
    else:
        sniffer = PacketSniffer()
        try:
            sniffer.start()
            while True:
                time.sleep(1)
                print(f"APs known: {len(sniffer.access_points)}")
        except KeyboardInterrupt:
            sniffer.stop()
