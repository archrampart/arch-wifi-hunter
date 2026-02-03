from scapy.all import *
import os

class Cracker:
    def __init__(self):
        pass
    
    def _get_aircrack_path(self):
        import shutil
        # Check specific locations first because environment path might be restricted in bundled app
        for path in ["/usr/local/bin/aircrack-ng", "/opt/homebrew/bin/aircrack-ng", "/usr/bin/aircrack-ng"]:
            if os.path.exists(path):
                return path
        # Fallback to shutil.which
        return shutil.which("aircrack-ng") or "aircrack-ng"

    def crack(self, pcap_file, wordlist_file, ssid, status_callback=None):
        import subprocess
        import re

        aircrack_bin = self._get_aircrack_path()


        def strip_ansi(text):
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)

        # Validate paths
        if not os.path.exists(pcap_file):
            if status_callback: status_callback(f"ERROR: Pcap file not found at {pcap_file}")
            return {"status": "error", "msg": "Capture file not found"}
        
        if not os.path.exists(wordlist_file):
            if status_callback: status_callback(f"ERROR: Wordlist file not found at {wordlist_file}")
            return {"status": "error", "msg": "Wordlist file not found"}

        try:
            cmd = [aircrack_bin, "-w", wordlist_file, "-e", ssid, pcap_file]
            
            if status_callback:
                status_callback(f"CMD: {' '.join(cmd)}")
                
                # Use stdbuf or unbuffered to try to help, but aircrack is TUI.
                # parsing stdout line by line.
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                
                key_found = False
                found_key = None
                
                for line in iter(self.process.stdout.readline, ''):
                    if not line: break
                    
                    # Log raw line for debugging (optional, maybe stripped better)
                    clean_line = strip_ansi(line).strip()
                    if clean_line:
                        status_callback(clean_line)
                    
                    if "KEY FOUND!" in clean_line:
                         # Regex to find content inside brackets: KEY FOUND! [ password ]
                         match = re.search(r'KEY FOUND!\s*\[\s*(.*?)\s*\]', clean_line)
                         if match:
                             found_key = match.group(1)
                             key_found = True
                             
                self.process.wait()
                self.process = None # Cleanup
                
                if key_found:
                    return {"status": "success", "key": found_key}
                else:
                    return {"status": "failed", "msg": "Password not found or stopped"}

            else:
                # Legacy / Fallback (No Callback)
                self.process = subprocess.run(cmd, capture_output=True, text=True)
                # ... existing logic ...
                # Wait, subprocess.run is blocking and returns CompletedProcess, not Popen.
                # Since we primarily use callback mode in main.py, I will focus on that.
                # But to be safe, let's just leave the else block mostly as is but using Popen is better for consistency?
                # Actually, status_callback is always passed from main.py.
                
                res = self.process
                self.process = None
                
                clean_output = strip_ansi(res.stdout)
                if "KEY FOUND!" in clean_output:
                     match = re.search(r'KEY FOUND!\s*\[\s*(.*?)\s*\]', clean_output)
                     if match:
                         return {"status": "success", "key": match.group(1)}
                
                return {"status": "failed", "msg": "Password not found (No Callback Mode)"}
                     
        except FileNotFoundError:
             if status_callback: status_callback("CRITICAL: aircrack-ng binary not found in PATH")
             return {"status": "error", "msg": "aircrack-ng not found on system. Install it via brew."}
        except Exception as e:
             return {"status": "error", "msg": f"Crack Error: {e}"}

    def stop_crack(self):
        if hasattr(self, 'process') and self.process:
            print("Stopping Cracking Process...")
            # If it's a Popen object
            if isinstance(self.process, subprocess.Popen):
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except:
                   self.process.kill()
            # If it was subprocess.run (CompletedProcess), it's already done, nothing to stop.
            self.process = None
            return True
        return False

    def export_hccapx(self, pcap_file, output_file):
        """
        Converts a pcap file to hccapx format using aircrack-ng.
        """
        import subprocess
        
        if not os.path.exists(pcap_file):
            return {"status": "error", "msg": "Capture file not found"}

        try:
            # aircrack-ng -J <output> <input>
            # Note: newer aircrack-ng uses -J for hccapx
            aircrack_bin = self._get_aircrack_path()
            cmd = [aircrack_bin, "-J", output_file, pcap_file]
            
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(output_file):
                 return {"status": "success", "file": output_file}
            else:
                 return {"status": "error", "msg": f"Conversion failed. Output: {res.stdout} {res.stderr}"}

        except Exception as e:
            return {"status": "error", "msg": str(e)}
