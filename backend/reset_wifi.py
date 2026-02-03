import subprocess
from backend.platform_wifi import IS_MACOS, IS_LINUX, detect_wifi_interface

if IS_MACOS:
    import objc
    from CoreWLAN import CWInterface

def reset_wifi():
    if IS_MACOS:
        _reset_macos()
    else:
        _reset_linux()

def _reset_macos():
    print("[*] Attempting to reset WiFi interface via CoreWLAN...")
    try:
        iface = CWInterface.interface()
        if iface:
            print(f"[*] Found interface: {iface.interfaceName()}")
            iface.disassociate()
            print("[+] Disassociate command sent.")
        else:
            print("[!] No default WiFi interface found.")
    except Exception as e:
        print(f"[!] Error resetting WiFi: {e}")

def _reset_linux():
    print("[*] Attempting to reset WiFi interface on Linux...")
    try:
        iface = detect_wifi_interface()
        # Stop monitor mode if active
        subprocess.run(["airmon-ng", "stop", iface], capture_output=True, timeout=10)
        subprocess.run(["airmon-ng", "stop", iface + "mon"], capture_output=True, timeout=10)

        # Bring interface back up
        orig = iface.replace("mon", "")
        subprocess.run(["ip", "link", "set", orig, "up"], capture_output=True, timeout=5)

        # Restart NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True, timeout=10)
        print(f"[+] WiFi reset complete. Interface: {orig}")
    except Exception as e:
        print(f"[!] Error resetting WiFi: {e}")

if __name__ == "__main__":
    reset_wifi()
