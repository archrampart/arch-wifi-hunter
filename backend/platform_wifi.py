"""
Platform abstraction for WiFi operations.
Detects macOS vs Linux and provides appropriate commands/paths.
"""
import platform
import subprocess
import glob
import os
import shutil

# Platform constants
PLATFORM = platform.system().lower()  # "darwin" or "linux"
IS_MACOS = PLATFORM == "darwin"
IS_LINUX = PLATFORM == "linux"

# macOS paths
AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


def _get_default_route_iface():
    """Get the interface that carries the default route (internet connection)."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split('\n'):
            if 'default' in line and 'dev' in line:
                parts = line.split()
                idx = parts.index('dev')
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return None


def detect_wifi_interface():
    """
    Auto-detect the primary WiFi interface.
    macOS: en0 (default, verified via networksetup)
    Linux: wlan0, wlan0mon, wlp*, etc.
    """
    if IS_MACOS:
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Wi-Fi' in line or 'AirPort' in line:
                    if i + 1 < len(lines) and 'Device:' in lines[i + 1]:
                        return lines[i + 1].split('Device:')[1].strip()
        except Exception:
            pass
        return "en0"

    else:  # Linux
        # Check for monitor mode interface first
        for pattern in ["wlan*mon", "wlx*mon"]:
            matches = sorted(glob.glob(f"/sys/class/net/{pattern}"))
            if matches:
                return os.path.basename(matches[0])

        # Prefer USB WiFi adapters (wlx*) over built-in (wlan0)
        # USB adapters like SXS Twin (MT7612U) show as wlxXXXXXXXXXXXX
        for pattern in ["wlx*", "wlp*s*u*"]:
            matches = sorted(glob.glob(f"/sys/class/net/{pattern}"))
            if matches:
                return os.path.basename(matches[0])

        # Then check standard wireless interfaces
        # When multiple wlan* exist (e.g. wlan0=internal WiFi, wlan1=USB adapter),
        # prefer the one that is NOT carrying the default route (internet).
        # The pentest adapter should be used for attacks, not the internet iface.
        for pattern in ["wlan*", "wlp*"]:
            matches = sorted(glob.glob(f"/sys/class/net/{pattern}"))
            if matches:
                if len(matches) > 1:
                    # Find which interface carries the default route
                    default_iface = _get_default_route_iface()
                    # Pick the first interface that is NOT the default route
                    for m in matches:
                        iface = os.path.basename(m)
                        if iface != default_iface:
                            return iface
                # Single match or all are default route — return first
                return os.path.basename(matches[0])

        # Fallback: parse iw dev
        try:
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Interface'):
                    return line.split()[-1]
        except Exception:
            pass

        return "wlan0"


def get_serial_patterns():
    """Return platform-specific serial device glob patterns."""
    if IS_MACOS:
        return [
            "/dev/tty.usbmodem*",
            "/dev/cu.usbmodem*",
            "/dev/tty.usbserial*",
            "/dev/cu.usbserial*",
        ]
    else:
        return [
            "/dev/ttyUSB*",
            "/dev/ttyACM*",
            "/dev/ttyS*",
        ]


def find_tool(name):
    """Find a tool binary, checking common paths per platform."""
    if IS_MACOS:
        search_paths = [
            f"/opt/homebrew/bin/{name}",
            f"/usr/local/bin/{name}",
            f"/usr/bin/{name}",
        ]
    else:
        search_paths = [
            f"/usr/bin/{name}",
            f"/usr/sbin/{name}",
            f"/usr/local/bin/{name}",
        ]

    for p in search_paths:
        if os.path.exists(p):
            return p

    return shutil.which(name) or name
