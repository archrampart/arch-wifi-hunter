import subprocess
import time
import os
import signal
from backend.platform_wifi import IS_MACOS, IS_LINUX

class MonitorController:
    def __init__(self, interface="en0"):
        self.interface = interface
        self.original_interface = interface  # Linux: wlan0 -> wlan0mon degisebilir
        self.tcpdump_process = None

    def enable_monitor_mode(self):
        """
        Enables monitor mode.
        macOS: tcpdump -I (background process)
        Linux: airmon-ng start <iface>
        """
        if self.is_monitor_mode_active():
            print(f"Monitor mode already active on {self.interface}")
            return True

        if IS_MACOS:
            return self._enable_macos()
        else:
            return self._enable_linux()

    def _enable_macos(self):
        """Enable monitor mode on macOS via tcpdump -I."""
        print(f"Enabling monitor mode on {self.interface} via tcpdump...")
        try:
            command = ["tcpdump", "-I", "-i", self.interface, "-w", "/dev/null"]
            self.tcpdump_process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)

            if self.tcpdump_process.poll() is None:
                print("Monitor mode enabled successfully.")
                return True
            else:
                print("Failed to enable monitor mode (tcpdump exited). Check permissions (sudo).")
                return False

        except Exception as e:
            print(f"Error enabling monitor mode: {e}")
            return False

    def _enable_linux(self):
        """Enable monitor mode on Linux via airmon-ng."""
        print(f"Enabling monitor mode on {self.interface} via airmon-ng...")
        try:
            # Kill interfering processes
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, text=True, timeout=10
            )

            # Start monitor mode
            result = subprocess.run(
                ["airmon-ng", "start", self.interface],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                print(f"airmon-ng failed: {result.stderr}")
                return False

            # Detect new interface name (wlan0 -> wlan0mon)
            new_iface = self._detect_monitor_interface()
            if new_iface:
                self.interface = new_iface
                print(f"Monitor mode enabled: {self.original_interface} -> {self.interface}")
                return True
            else:
                print("Monitor mode enabled but could not detect monitor interface.")
                return False

        except FileNotFoundError:
            print("airmon-ng not found. Install aircrack-ng suite.")
            return False
        except Exception as e:
            print(f"Error enabling monitor mode: {e}")
            return False

    def _detect_monitor_interface(self):
        """Detect the monitor mode interface name on Linux."""
        import glob as glob_mod

        # Check common patterns: wlan0mon, wlan0
        mon_name = self.original_interface + "mon"
        if os.path.exists(f"/sys/class/net/{mon_name}"):
            return mon_name

        # Original interface might stay the same
        if os.path.exists(f"/sys/class/net/{self.original_interface}"):
            # Check if it's now in monitor mode
            try:
                result = subprocess.run(
                    ["iw", "dev", self.original_interface, "info"],
                    capture_output=True, text=True, timeout=5
                )
                if "monitor" in result.stdout.lower():
                    return self.original_interface
            except Exception:
                pass

        # Search for any monitor interface
        for pattern in ["wlan*mon", "wlan*", "wlp*", "wlx*"]:
            matches = sorted(glob_mod.glob(f"/sys/class/net/{pattern}"))
            for match in matches:
                iface = os.path.basename(match)
                try:
                    result = subprocess.run(
                        ["iw", "dev", iface, "info"],
                        capture_output=True, text=True, timeout=5
                    )
                    if "monitor" in result.stdout.lower():
                        return iface
                except Exception:
                    continue

        return None

    def disable_monitor_mode(self):
        """
        Disables monitor mode.
        macOS: kills tcpdump process.
        Linux: airmon-ng stop + restart NetworkManager.
        """
        if IS_MACOS:
            self._disable_macos()
        else:
            self._disable_linux()

    def _disable_macos(self):
        """Disable monitor mode on macOS."""
        if self.tcpdump_process:
            print("Stopping tcpdump (disabling monitor mode)...")
            self.tcpdump_process.terminate()
            try:
                self.tcpdump_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.tcpdump_process.kill()
            self.tcpdump_process = None
            print("Monitor mode disabled.")
        else:
            print("Monitor mode was not active managed by this controller.")

    def _disable_linux(self):
        """Disable monitor mode on Linux via airmon-ng."""
        print(f"Disabling monitor mode on {self.interface}...")
        try:
            subprocess.run(
                ["airmon-ng", "stop", self.interface],
                capture_output=True, text=True, timeout=10
            )
            # Restore original interface name
            self.interface = self.original_interface
            print(f"Monitor mode disabled. Interface restored to {self.interface}")

            # Restart NetworkManager
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                capture_output=True, text=True, timeout=10
            )
        except Exception as e:
            print(f"Error disabling monitor mode: {e}")

    def is_monitor_mode_active(self):
        if IS_MACOS:
            return self.tcpdump_process is not None and self.tcpdump_process.poll() is None
        else:
            # Linux: check if monitor interface exists
            if self.interface != self.original_interface:
                return os.path.exists(f"/sys/class/net/{self.interface}")
            # Check if original interface is in monitor mode
            try:
                result = subprocess.run(
                    ["iw", "dev", self.interface, "info"],
                    capture_output=True, text=True, timeout=5
                )
                return "monitor" in result.stdout.lower()
            except Exception:
                return False

    @staticmethod
    def check_root():
        return os.geteuid() == 0

if __name__ == "__main__":
    if not MonitorController.check_root():
        print("Please run as root.")
    else:
        mon = MonitorController()
        try:
            mon.enable_monitor_mode()
            print("Running for 5 seconds...")
            time.sleep(5)
        finally:
            mon.disable_monitor_mode()
