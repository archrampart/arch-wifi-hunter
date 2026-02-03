"""
OUI (Organizationally Unique Identifier) Lookup Module
Provides MAC address vendor lookup functionality using IEEE OUI database.
"""

import os
from typing import Optional, Dict

class OUILookup:
    """
    OUI Lookup class for resolving MAC addresses to vendor names.
    Uses IEEE OUI database (oui.txt) for vendor identification.
    """

    def __init__(self, oui_file_path: str = None):
        """
        Initialize OUI Lookup with database file.

        Args:
            oui_file_path: Path to oui.txt file. If None, uses default location.
        """
        if oui_file_path is None:
            # Default to parent directory's oui.txt
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            oui_file_path = os.path.join(parent_dir, 'oui.txt')

        self.oui_file = oui_file_path
        self.oui_cache: Dict[str, str] = {}
        self._load_oui_database()

    def _load_oui_database(self):
        """
        Load OUI database into memory cache.
        Only loads the hex format entries for efficiency.
        """
        if not os.path.exists(self.oui_file):
            print(f"⚠️  OUI file not found at {self.oui_file}")
            return

        try:
            with open(self.oui_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Look for hex format lines: "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
                    if '(hex)' in line:
                        parts = line.split('(hex)')
                        if len(parts) >= 2:
                            # Extract MAC prefix and vendor name
                            mac_prefix = parts[0].strip().replace('-', '').upper()
                            vendor = parts[1].strip()

                            # Store in cache
                            if mac_prefix and vendor:
                                self.oui_cache[mac_prefix] = vendor

            print(f"✅ Loaded {len(self.oui_cache)} OUI entries")

        except Exception as e:
            print(f"❌ Error loading OUI database: {e}")

    def lookup(self, mac_address: str) -> Optional[str]:
        """
        Lookup vendor name from MAC address.

        Args:
            mac_address: MAC address in any format (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX)

        Returns:
            Vendor name if found, None otherwise
        """
        if not mac_address:
            return None

        # Clean MAC address - remove separators and convert to uppercase
        clean_mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()

        # MAC address must be at least 6 characters (OUI is first 3 bytes = 6 hex chars)
        if len(clean_mac) < 6:
            return None

        # Extract OUI (first 6 characters)
        oui = clean_mac[:6]

        # Lookup in cache
        return self.oui_cache.get(oui)

    def get_vendor_info(self, mac_address: str) -> Dict[str, str]:
        """
        Get detailed vendor information for a MAC address.

        Args:
            mac_address: MAC address in any format

        Returns:
            Dictionary with 'vendor' and 'oui' fields
        """
        vendor = self.lookup(mac_address)
        clean_mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
        oui = clean_mac[:6] if len(clean_mac) >= 6 else None

        return {
            'vendor': vendor or 'Unknown',
            'oui': oui
        }


# Global instance for easy access
_global_oui_lookup = None

def get_oui_lookup() -> OUILookup:
    """
    Get global OUI lookup instance (singleton pattern).

    Returns:
        Global OUILookup instance
    """
    global _global_oui_lookup
    if _global_oui_lookup is None:
        _global_oui_lookup = OUILookup()
    return _global_oui_lookup


# Convenience function
def lookup_mac_vendor(mac_address: str) -> str:
    """
    Quick lookup function for MAC address vendor.

    Args:
        mac_address: MAC address in any format

    Returns:
        Vendor name or 'Unknown'
    """
    oui = get_oui_lookup()
    vendor = oui.lookup(mac_address)
    return vendor if vendor else 'Unknown'
