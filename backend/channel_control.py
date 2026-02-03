import subprocess
from backend.platform_wifi import IS_MACOS, IS_LINUX

if IS_MACOS:
    import objc
    from CoreWLAN import CWInterface, CWWiFiClient

class ChannelController:
    def __init__(self, interface_name="en0"):
        self.interface_name = interface_name

        if IS_MACOS:
            self.client = CWWiFiClient.sharedWiFiClient()
            self.interface = self.client.interface()  # Default interface
            if self.interface and self.interface.interfaceName() != interface_name:
                self.interface = self.client.interfaceWithName_(interface_name)
        else:
            self.interface = None  # Linux uses iw commands

    def set_channel(self, channel_number, band_ghz=2.4):
        """
        Sets the WiFi channel. Uses CoreWLAN on macOS, iw on Linux.
        Returns True on success, False on failure.
        """
        if IS_MACOS:
            return self._set_channel_macos(channel_number)
        else:
            return self._set_channel_linux(channel_number)

    def _set_channel_macos(self, channel_number):
        """Set channel using CoreWLAN on macOS."""
        if not self.interface:
            print("No WiFi interface found.")
            return False

        try:
            channels = self.interface.supportedWLANChannels()
            target_channel = None

            for ch in channels:
                if ch.channelNumber() == channel_number:
                    target_channel = ch
                    break

            if not target_channel:
                print(f"Channel {channel_number} not supported.")
                return False

            print(f"Switching to channel {channel_number}...")
            self.interface.disassociate()

            success, error = self.interface.setWLANChannel_error_(target_channel, None)

            if success:
                print(f"Successfully switched to channel {channel_number}")
                return True
            else:
                print(f"Failed to switch channel: {error}")
                return False

        except Exception as e:
            print(f"Error switching channel: {e}")
            return False

    def _set_channel_linux(self, channel_number):
        """Set channel using iw on Linux."""
        try:
            result = subprocess.run(
                ["iw", "dev", self.interface_name, "set", "channel", str(channel_number)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                print(f"Successfully switched to channel {channel_number}")
                return True
            else:
                # Fallback to iwconfig
                result = subprocess.run(
                    ["iwconfig", self.interface_name, "channel", str(channel_number)],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    print(f"Successfully switched to channel {channel_number} (iwconfig)")
                    return True
                else:
                    print(f"Failed to switch channel: {result.stderr}")
                    return False
        except Exception as e:
            print(f"Error switching channel: {e}")
            return False

    def get_current_channel(self):
        if IS_MACOS:
            if self.interface and self.interface.wlanChannel():
                return self.interface.wlanChannel().channelNumber()
            return None
        else:
            try:
                result = subprocess.run(
                    ["iw", "dev", self.interface_name, "info"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('channel'):
                        return int(line.split()[1])
            except Exception:
                pass
            return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        ch = int(sys.argv[1])
        cc = ChannelController()
        cc.set_channel(ch)
    else:
        cc = ChannelController()
        print(f"Current Channel: {cc.get_current_channel()}")
