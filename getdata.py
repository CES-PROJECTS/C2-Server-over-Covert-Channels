from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from base64 import b64decode
import json
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
AES_KEY = b'mysecretaeskey12'
AES_IV = b'initialvector123'
DATA_DIR  = 'DATA'

# Ensure data directory exists
os.makedirs(DATA_DIR , exist_ok=True)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_data(encrypted_b64):
    try:
        encrypted_bytes = b64decode(encrypted_b64)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(encrypted_bytes)
        return unpad(decrypted).decode('utf-8')
    except Exception as e:
        return None

def log_data(device_id, content):
    try:
        today_str = datetime.now().strftime("%Y-%m-%d")
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Device folder
        device_path = os.path.join(DATA_DIR , device_id)
        os.makedirs(device_path, exist_ok=True)

        # Day-wise file
        file_path = os.path.join(device_path, f"{today_str}.log")

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"{timestamp} ::\n{content}\n\n")
    except Exception as e:
        print("[!] Logging failed:", e)

@app.route('/api/track', methods=['POST'])
def receive_data():
    if request.content_type != 'application/json':
        return jsonify({'error': 'Unsupported Media Type'}), 415

    try:
        data = request.get_json()
        enc_payload = data.get('data')
        if not enc_payload:
            return jsonify({'error': 'Missing "data" field'}), 400
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400

    decrypted_data = decrypt_data(enc_payload)
    if decrypted_data is None:
        return jsonify({'error': 'Decryption failed'}), 422

    try:
        parsed = json.loads(decrypted_data)
    except Exception:
        return jsonify({'error': 'Invalid decrypted JSON'}), 406

    # Extract device ID if sent (optional)
    device_id = parsed.get("device_id", "unknown_device")
    result = parsed.get("result", "")

    # Time formatting
    now = datetime.now()
    time_str = now.strftime('%H:%M:%S')
    date_str = now.strftime('%Y-%m-%d')

    # Folder structure
    device_folder = os.path.join(DATA_DIR, device_id)
    os.makedirs(device_folder, exist_ok=True)

    file_path = os.path.join(device_folder, f"{date_str}.log")

    # Save formatted result to file
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{time_str} ::\n{result}\n\n")
    except Exception as e:
        print(f"[!] Failed to write log: {e}")

    # Also print it (for live debug)
    print(f"[+] {device_id} @ {time_str}:\n{result}\n")

    return jsonify({'status': 'ok', 'code': 200}), 200
@app.route('/')
def default_route():
    return "Telemetry endpoint active", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8841)
