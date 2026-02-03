"""
Beacon Flood Module for ARCH // HUNTER
Uses mdk4 for broadcasting fake beacon frames (SSIDs).
Linux (Kali) only - requires mdk4, monitor mode support.
"""
import subprocess
import threading
import time
import os
import re
from datetime import datetime
from backend.platform_wifi import IS_LINUX, find_tool


class BeaconFloodManager:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.running = False
        self.starting = False
        self.process = None
        self.target_channel = None
        self.ssid_count = 0
        self.speed = 50
        self.mode = "random"  # "random", "manual", "file"
        self._output_lines = []
        self._start_time = None
        self._log_callback = None
        self._ssid_file = "/tmp/beacon_flood_ssids.txt"

    def start(self, ssid_list=None, channel=0, speed=50, mode="random", callback=None):
        """Start beacon flood attack."""
        if not IS_LINUX:
            return {"status": "error", "message": "Beacon flood only works on Linux (Kali)"}

        if self.running or self.starting:
            return {"status": "error", "message": "Beacon flood already running"}

        # Check tools
        mdk4_bin = find_tool("mdk4")
        if not mdk4_bin or not os.path.exists(mdk4_bin):
            return {"status": "error", "message": "mdk4 not found. Install with: apt install mdk4"}

        self.starting = True
        self.target_channel = channel if channel > 0 else None
        self.speed = speed
        self.mode = mode
        self.ssid_count = len(ssid_list) if ssid_list else 0
        self._output_lines = []
        self._log_callback = callback

        # Run in background thread
        thread = threading.Thread(
            target=self._run_attack,
            args=(ssid_list or [], channel, speed, mode, callback),
            daemon=True
        )
        thread.start()

        return {"status": "success", "message": f"Beacon flood starting ({mode} mode)..."}

    def _run_attack(self, ssid_list, channel, speed, mode, callback):
        """Background thread: setup monitor mode and run mdk4."""
        def _log(msg):
            """Log to both print (backend terminal) and callback (frontend)."""
            print(f"[FLOOD] {msg}")
            if callback:
                try:
                    callback(msg)
                except Exception as cb_err:
                    print(f"[FLOOD] Callback error: {cb_err}")

        try:
            _log(f"Thread started. Interface={self.interface}, mode={mode}, "
                 f"ssids={len(ssid_list)}, channel={channel}, speed={speed}")

            # Wait for any in-progress scan to finish
            _log("Waiting 3s for any in-progress scan to finish...")
            time.sleep(3)

            # Step 1: Kill interfering processes
            _log("Step 1: Killing interfering processes...")
            r = subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, text=True, timeout=10
            )
            _log(f"airmon-ng check kill: rc={r.returncode}")
            if r.stdout.strip():
                for line in r.stdout.strip().split('\n')[-3:]:
                    _log(f"  {line.strip()}")
            if r.stderr.strip():
                _log(f"  stderr: {r.stderr.strip()}")
            time.sleep(1)

            # Step 2: Set monitor mode
            _log(f"Step 2: Setting monitor mode on {self.interface}...")

            r1 = subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                capture_output=True, text=True, timeout=5
            )
            _log(f"  ip link set down: rc={r1.returncode} stderr={r1.stderr.strip()}")

            r2 = subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "monitor"],
                capture_output=True, text=True, timeout=5
            )
            _log(f"  iw set monitor: rc={r2.returncode} stderr={r2.stderr.strip()}")

            r3 = subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                capture_output=True, text=True, timeout=5
            )
            _log(f"  ip link set up: rc={r3.returncode} stderr={r3.stderr.strip()}")

            if r2.returncode != 0:
                _log(f"ERROR: Failed to set monitor mode: {r2.stderr.strip()}")
                return

            time.sleep(1)

            # Step 3: Verify monitor mode
            _log("Step 3: Verifying monitor mode...")
            r_verify = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            for line in r_verify.stdout.strip().split('\n'):
                _log(f"  {line.strip()}")

            if "type monitor" not in r_verify.stdout:
                _log("ERROR: Interface is NOT in monitor mode! Aborting.")
                return

            _log("Monitor mode confirmed.")

            # Step 4: Set channel
            # mdk4 beacon flood targets 2.4GHz channels (1-13).
            # We MUST set the interface to a 2.4GHz channel, otherwise
            # if the interface is stuck on a 5GHz channel, beacons won't be visible.
            effective_channel = channel if channel and channel > 0 else 1
            _log(f"Step 4: Setting channel {effective_channel}{'  (default — user selected all)' if not (channel and channel > 0) else ''}...")
            r_ch = subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(effective_channel)],
                capture_output=True, text=True, timeout=5
            )
            _log(f"  Channel set: rc={r_ch.returncode} stderr={r_ch.stderr.strip()}")

            self.starting = False
            self.running = True
            self._start_time = time.time()

            # Step 5: Write SSID file if manual/file mode
            use_ssid_file = False
            if ssid_list and len(ssid_list) > 0:
                with open(self._ssid_file, 'w') as f:
                    for ssid in ssid_list:
                        f.write(ssid.strip() + '\n')
                use_ssid_file = True
                _log(f"Step 5: Wrote {len(ssid_list)} SSIDs to {self._ssid_file}")

            # Step 6: Build and run mdk4 command
            mdk4_bin = find_tool("mdk4")
            _log(f"Step 6: mdk4 binary path = {mdk4_bin}")
            _log(f"  mdk4 exists = {os.path.exists(mdk4_bin)}")

            cmd = [mdk4_bin, self.interface, "b"]

            if use_ssid_file:
                cmd.extend(["-f", self._ssid_file])

            # speed=0 means max speed (don't pass -s flag, let mdk4 go full throttle)
            if speed and speed > 0:
                cmd.extend(["-s", str(speed)])

            # Always pass channel to mdk4 so beacons go on the correct 2.4GHz channel
            cmd.extend(["-c", str(effective_channel)])

            _log(f"CMD: {' '.join(cmd)}")

            # Start mdk4 process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1  # Line buffered
            )

            _log(f"mdk4 started (PID: {self.process.pid})")

            # Read output in real-time
            while self.running and self.process:
                line = self.process.stdout.readline()
                if not line:
                    # Process ended or pipe closed
                    break

                clean = line.strip()
                if not clean:
                    continue

                self._output_lines.append(clean)
                _log(f"mdk4> {clean}")

            # Check exit code
            if self.process:
                exit_code = self.process.wait()
                _log(f"mdk4 exited with code: {exit_code}")
                if exit_code != 0:
                    # Try to get any remaining stderr
                    try:
                        remaining = self.process.stdout.read()
                        if remaining and remaining.strip():
                            _log(f"mdk4 remaining output: {remaining.strip()}")
                    except Exception:
                        pass
                self.process = None

            _log("Beacon flood finished.")

        except Exception as e:
            _log(f"EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
            self.starting = False
            self.process = None
            _log("Restoring interface...")
            self._restore_interface()
            self._cleanup_ssid_file()
            _log("Cleanup complete.")

    def stop(self):
        """Stop the running beacon flood."""
        if not self.running and not self.starting:
            return {"status": "error", "message": "No beacon flood running"}

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

        # Kill any remaining mdk4 processes
        try:
            subprocess.run(
                ["pkill", "-f", "mdk4"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        self._restore_interface()
        self._cleanup_ssid_file()

        return {"status": "success", "message": "Beacon flood stopped"}

    def _restore_interface(self):
        """Restore interface to managed mode and restart NetworkManager."""
        print("[FLOOD] Restoring interface to managed mode...")
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
        print("[FLOOD] Interface restored to managed mode")

    def _cleanup_ssid_file(self):
        """Remove temporary SSID file."""
        try:
            if os.path.exists(self._ssid_file):
                os.remove(self._ssid_file)
        except Exception:
            pass

    def get_status(self):
        """Get current beacon flood status."""
        elapsed = 0
        if self._start_time and self.running:
            elapsed = int(time.time() - self._start_time)

        return {
            "running": self.running,
            "starting": self.starting,
            "target_channel": self.target_channel,
            "ssid_count": self.ssid_count,
            "speed": self.speed,
            "mode": self.mode,
            "elapsed_seconds": elapsed,
            "output_lines": self._output_lines[-5:] if self._output_lines else []
        }
