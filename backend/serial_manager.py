import serial
import serial.tools.list_ports
import threading
import time
import asyncio
from backend.platform_wifi import get_serial_patterns

class SerialManager:
    def __init__(self):
        self.serial_port = None
        self.is_connected = False
        self.read_thread = None
        self.buffer = [] # Store last lines of output
        self.lock = threading.Lock()

    def list_ports(self):
        """Returns list of available serial ports, including manual glob for macOS."""
        # 1. Standard PySerial List
        ports = [{"device": p.device, "description": p.description} for p in serial.tools.list_ports.comports()]
        
        # 2. Manual Glob for platform-specific serial devices
        import glob
        manual_ports = []
        for pattern in get_serial_patterns():
            manual_ports.extend(glob.glob(pattern))
        
        existing_devices = {p["device"] for p in ports}
        
        for mp in manual_ports:
            if mp not in existing_devices:
                ports.append({"device": mp, "description": "Manual Detection"})
        
        print(f"[SERIAL DEBUG] Found ports: {[p['device'] for p in ports]}")
        return ports

    def auto_connect(self):
        """Attempts to find and connect to a known Flipper/ESP device automatically."""
        import glob
        # Priority list of patterns (platform-specific)
        patterns = get_serial_patterns()
        
        candidates = []
        for p in patterns:
            # Sort within glob results to be deterministic
            matches = sorted(glob.glob(p))
            for m in matches:
                if m not in candidates:
                    candidates.append(m)
        
        if not candidates:
             # Fallback to pyserial's list if glob fails
             candidates = [p.device for p in serial.tools.list_ports.comports()]
        
        # Sort candidates to force tty before cu
        # Heuristic: 'tty' comes before 'cu' in alphabetical, but let's be explicit
        candidates.sort(key=lambda x: 0 if 'tty' in x else 1)

        print(f"[SERIAL AUTO] Candidates (Sorted): {candidates}")
        
        for port in candidates:
            # Skip bluetooth or debug ports
            if "Bluetooth" in port or "debug" in port:
                continue
                
            print(f"[SERIAL AUTO] Trying {port}...")
            try:
                # Try to connect
                success, msg = self.connect(port)
                if success:
                    return True, f"Connected to {port}"
                else:
                    print(f"[SERIAL AUTO] Failed {port}: {msg}")
                    self.disconnect() # Clean up failed attempt
            except Exception as e:
                print(f"[SERIAL AUTO] CRASH on {port}: {str(e)}")
                import traceback
                traceback.print_exc()
                
        return False, "No suitable device found. Is it plugged in?"

    def connect(self, port, baudrate=115200):
        if self.serial_port and self.serial_port.is_open:
            self.disconnect()
        
        try:
            print(f"[SERIAL DEBUG] Opening {port}...")
             # DSR/DTR and RTS/CTS must be False for most USB-Serial CDC
             # write_timeout prevents blocking forever
            self.serial_port = serial.Serial(port, baudrate, timeout=1, write_timeout=0.5, dsrdtr=False, rtscts=False)
            print("[SERIAL DEBUG] Port object created.")
            
            # Explicitly assert DTR/RTS to wake up device (vital for ESP32/Flipper)
            self.serial_port.dtr = True
            self.serial_port.rts = True
            print("[SERIAL DEBUG] DTR/RTS asserted.")
            
            self.is_connected = True
            
            # Send wakeup newline to trigger CLI prompt (Best Effort)
            # SKIPPING WRITE FOR NOW to prevent TTY hang on macOS
            # try:
            #     time.sleep(0.5)
            #     self.serial_port.write(b"\r\n")
            #     print("[SERIAL DEBUG] Wakeup sent.")
            # except Exception as w_err:
            #      print(f"[SERIAL DEBUG] Wakeup write failed (non-fatal): {w_err}")
            
            print("[SERIAL DEBUG] Skipping wakeup write to ensure connection.")

            # Start Read Thread
            self.stop_reading = False
            self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
            self.read_thread.start()
            
            print("[SERIAL DEBUG] Read thread started. SUCCESS.")
            return True, "Connected"
        except Exception as e:
            print(f"[SERIAL DEBUG] ERROR in connect: {e}")
            self.is_connected = False
            return False, str(e)

    def disconnect(self):
        self.stop_reading = True
        if self.serial_port:
            try:
                self.serial_port.close()
            except:
                pass
        self.serial_port = None
        self.is_connected = False

    def write(self, command):
        if not self.is_connected or not self.serial_port:
            return False, "Not Connected"
        
        try:
            # Marauder usually expects \n
            if not command.endswith('\n'):
                command += '\n'
            self.serial_port.write(command.encode('utf-8'))
            return True, "Sent"
        except Exception as e:
            return False, str(e)

    def _read_loop(self):
        while self.is_connected and self.serial_port and not self.stop_reading:
            try:
                if self.serial_port.in_waiting > 0:
                    line = self.serial_port.readline().decode('utf-8', errors='replace').strip()
                    if line:
                        with self.lock:
                            self.buffer.append(line)
                            if len(self.buffer) > 100: # Keep last 100 lines
                                self.buffer.pop(0)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[SERIAL] Read Error: {e}")
                break

    def get_logs(self):
        with self.lock:
            # Return copy of buffer
            return list(self.buffer)

# Global Instance
serial_manager = SerialManager()
