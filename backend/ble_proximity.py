import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional

# ===================================================================================
# BLE PROXIMITY & MAC RANDOMIZATION DETECTION
# ===================================================================================
# Features:
# 1. Distance estimation from RSSI
# 2. Proximity alerts (configurable thresholds)
# 3. MAC randomization pattern detection (Apple/Android)
# 4. Device tracking & history
# ===================================================================================

@dataclass
class ProximityAlert:
    """Proximity alert configuration"""
    mac: str
    threshold_meters: float
    alert_type: str  # "enter" or "exit"
    last_triggered: float = 0.0
    cooldown: float = 5.0  # Seconds between alerts

@dataclass
class DeviceHistory:
    """Device tracking history"""
    mac: str
    rssi_history: deque  # Last N RSSI values
    distance_history: deque  # Last N distance estimates
    first_seen: float
    last_seen: float
    appearance_count: int = 1
    vendor: str = "Unknown"
    is_random_mac: bool = False
    random_mac_confidence: float = 0.0  # 0.0 - 1.0


class BLEProximityManager:
    """Manages proximity alerts and MAC randomization detection"""

    def __init__(self):
        # Proximity tracking
        self.device_history: Dict[str, DeviceHistory] = {}
        self.alerts: List[ProximityAlert] = []
        self.triggered_alerts: List[dict] = []

        # MAC Randomization tracking
        self.random_mac_patterns: Dict[str, dict] = {}

        # RSSI to distance parameters (Path Loss model)
        # d = 10^((TxPower - RSSI) / (10 * n))
        self.tx_power = -59  # Typical BLE TX power at 1m
        self.path_loss_exponent = 2.5  # Environment factor (2.0-4.0)

        # History size
        self.history_size = 10

    # ===================================================================================
    # DISTANCE ESTIMATION (RSSI → Meters)
    # ===================================================================================

    def rssi_to_distance(self, rssi: int) -> float:
        """
        Convert RSSI to distance estimate in meters.
        Uses Path Loss model: d = 10^((TxPower - RSSI) / (10 * n))

        Args:
            rssi: Signal strength in dBm

        Returns:
            Estimated distance in meters
        """
        if rssi == 0:
            return -1.0  # Unknown

        ratio = (self.tx_power - rssi) / (10 * self.path_loss_exponent)
        distance = math.pow(10, ratio)

        # Clamp to reasonable values
        return max(0.1, min(distance, 100.0))

    def get_smoothed_distance(self, mac: str) -> Optional[float]:
        """Get smoothed distance estimate using moving average"""
        if mac not in self.device_history:
            return None

        history = self.device_history[mac]
        if len(history.distance_history) == 0:
            return None

        # Moving average
        return sum(history.distance_history) / len(history.distance_history)

    # ===================================================================================
    # DEVICE TRACKING & HISTORY
    # ===================================================================================

    def update_device(self, mac: str, rssi: int, vendor: str = "Unknown"):
        """Update device tracking data"""
        current_time = time.time()
        distance = self.rssi_to_distance(rssi)

        if mac not in self.device_history:
            # New device
            self.device_history[mac] = DeviceHistory(
                mac=mac,
                rssi_history=deque(maxlen=self.history_size),
                distance_history=deque(maxlen=self.history_size),
                first_seen=current_time,
                last_seen=current_time,
                vendor=vendor
            )

        history = self.device_history[mac]
        history.rssi_history.append(rssi)
        history.distance_history.append(distance)
        history.last_seen = current_time
        history.appearance_count += 1

        # Check for MAC randomization
        self._analyze_mac_randomization(mac, vendor, current_time)

        # Check proximity alerts
        self._check_proximity_alerts(mac, distance, current_time)

    def _analyze_mac_randomization(self, mac: str, vendor: str, current_time: float):
        """
        Detect MAC address randomization patterns.

        Random MAC indicators:
        1. Locally administered bit set (2nd char is 2, 6, A, E)
        2. Short appearance duration
        3. Apple/Google vendor with changing MAC
        4. Similar RSSI pattern with different MACs
        """
        history = self.device_history[mac]

        # Check locally administered bit (random MAC indicator)
        second_char = mac[1].upper()
        is_local_bit_set = second_char in ['2', '6', 'A', 'E']

        confidence = 0.0
        reasons = []

        # Indicator 1: Local bit set
        if is_local_bit_set:
            confidence += 0.4
            reasons.append("Local admin bit set")

        # Indicator 2: Apple/Android vendor
        if vendor in ["Apple", "Google"]:
            confidence += 0.3
            reasons.append(f"{vendor} device (uses random MAC)")

        # Indicator 3: Short-lived device (disappears quickly)
        if history.appearance_count < 5 and (current_time - history.first_seen) < 30:
            confidence += 0.2
            reasons.append("Short-lived appearance")

        # Indicator 4: OUI is known random MAC range
        oui = mac[:8].upper()
        if self._is_known_random_oui(oui):
            confidence += 0.3
            reasons.append("Known random MAC OUI")

        # Update detection
        history.is_random_mac = confidence >= 0.5
        history.random_mac_confidence = min(confidence, 1.0)

        if history.is_random_mac and mac not in self.random_mac_patterns:
            self.random_mac_patterns[mac] = {
                "first_seen": history.first_seen,
                "confidence": history.random_mac_confidence,
                "reasons": reasons,
                "vendor": vendor
            }

    def _is_known_random_oui(self, oui: str) -> bool:
        """Check if OUI is in known random MAC ranges"""
        # Apple random MAC OUIs (partial list)
        apple_random = ["02:00:00", "06:00:00", "0A:00:00", "0E:00:00"]

        # Android random MAC patterns
        android_random = ["DA:A1:19", "02:00:00"]

        for pattern in apple_random + android_random:
            if oui.startswith(pattern):
                return True

        return False

    # ===================================================================================
    # PROXIMITY ALERTS
    # ===================================================================================

    def add_alert(self, mac: str, threshold_meters: float, alert_type: str = "enter"):
        """
        Add proximity alert for a device.

        Args:
            mac: Device MAC address
            threshold_meters: Distance threshold in meters
            alert_type: "enter" (closer than) or "exit" (farther than)
        """
        alert = ProximityAlert(
            mac=mac,
            threshold_meters=threshold_meters,
            alert_type=alert_type
        )
        self.alerts.append(alert)

    def remove_alert(self, mac: str):
        """Remove all alerts for a device"""
        self.alerts = [a for a in self.alerts if a.mac != mac]

    def _check_proximity_alerts(self, mac: str, distance: float, current_time: float):
        """Check if any proximity alerts should trigger"""
        for alert in self.alerts:
            if alert.mac != mac:
                continue

            # Cooldown check
            if current_time - alert.last_triggered < alert.cooldown:
                continue

            # Threshold check
            triggered = False
            if alert.alert_type == "enter" and distance <= alert.threshold_meters:
                triggered = True
            elif alert.alert_type == "exit" and distance >= alert.threshold_meters:
                triggered = True

            if triggered:
                alert.last_triggered = current_time

                # Store triggered alert
                self.triggered_alerts.append({
                    "mac": mac,
                    "distance": round(distance, 2),
                    "threshold": alert.threshold_meters,
                    "type": alert.alert_type,
                    "timestamp": current_time,
                    "vendor": self.device_history[mac].vendor if mac in self.device_history else "Unknown"
                })

    def get_triggered_alerts(self, clear: bool = True) -> List[dict]:
        """Get and optionally clear triggered alerts"""
        alerts = self.triggered_alerts.copy()
        if clear:
            self.triggered_alerts.clear()
        return alerts

    # ===================================================================================
    # DATA ACCESS & EXPORT
    # ===================================================================================

    def get_device_info(self, mac: str) -> Optional[dict]:
        """Get detailed info for a device"""
        if mac not in self.device_history:
            return None

        history = self.device_history[mac]
        distance = self.get_smoothed_distance(mac)

        return {
            "mac": mac,
            "vendor": history.vendor,
            "distance": round(distance, 2) if distance else None,
            "rssi_avg": round(sum(history.rssi_history) / len(history.rssi_history), 1) if history.rssi_history else None,
            "first_seen": history.first_seen,
            "last_seen": history.last_seen,
            "duration": round(history.last_seen - history.first_seen, 1),
            "appearance_count": history.appearance_count,
            "is_random_mac": history.is_random_mac,
            "random_mac_confidence": round(history.random_mac_confidence, 2)
        }

    def get_all_devices(self) -> List[dict]:
        """Get info for all tracked devices"""
        return [self.get_device_info(mac) for mac in self.device_history.keys()]

    def get_random_mac_devices(self) -> List[dict]:
        """Get all devices detected with MAC randomization"""
        result = []
        for mac, pattern in self.random_mac_patterns.items():
            info = self.get_device_info(mac)
            if info:
                info["detection_reasons"] = pattern["reasons"]
                result.append(info)
        return result

    def cleanup_old_devices(self, max_age: float = 300.0):
        """Remove devices not seen for max_age seconds"""
        current_time = time.time()
        expired = []

        for mac, history in self.device_history.items():
            if current_time - history.last_seen > max_age:
                expired.append(mac)

        for mac in expired:
            del self.device_history[mac]
            if mac in self.random_mac_patterns:
                del self.random_mac_patterns[mac]

    # ===================================================================================
    # STATISTICS
    # ===================================================================================

    def get_statistics(self) -> dict:
        """Get proximity system statistics"""
        current_time = time.time()

        active_devices = sum(
            1 for h in self.device_history.values()
            if current_time - h.last_seen < 30
        )

        random_mac_count = sum(
            1 for h in self.device_history.values()
            if h.is_random_mac
        )

        return {
            "total_devices": len(self.device_history),
            "active_devices": active_devices,
            "random_mac_devices": random_mac_count,
            "active_alerts": len(self.alerts),
            "triggered_alerts": len(self.triggered_alerts)
        }


# ===================================================================================
# GLOBAL INSTANCE
# ===================================================================================
proximity_manager = BLEProximityManager()
