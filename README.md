# Custom C2 Server with Encrypted DNS and HTTPS Channels

A custom-built Command & Control (C2) infrastructure for research and education purposes. This project showcases how to securely issue commands and receive data from remote agents using encrypted DNS TXT records for inbound control and HTTPS for outbound telemetry.

> ⚠️ **Disclaimer:** This project is strictly intended for educational, academic, and ethical red team simulation purposes. Do not deploy or use it on any system without full authorization.

---

## 🔧 Components

### 1. **Command Generator**
- Encrypts structured command JSON using AES-128-CBC.
- Encodes encrypted data into a base64 string suitable for DNS TXT records.

### 2. **Agent/Bot**
- Periodically fetches and decrypts DNS TXT records for commands.
- Executes commands or payloads and returns results via HTTPS.
- Generates unique `device_id` from system BIOS/UUID info.

### 3. **Result Receiver (REST API)**
- Flask-based server listening for encrypted result logs.
- Decrypts and stores results by device and timestamp.

---

## 💡 How It Works

1. **Generate Encrypted Commands:**
   - Use `dns_command_gen.py` to create encrypted instructions.
   - Upload the output as a TXT record in your DNS provider.

2. **Agent Execution:**
   - The agent resolves the TXT record, decrypts it, and:
     - Executes commands.
     - Runs embedded executables.
     - Sends back results via HTTPS.

3. **Telemetry Server:**
   - Receives encrypted results from agents at `/api/track`.
   - Stores logs device-wise for later review.

---

## 📂 Project Structure

```

Custom-C2/
├── agent.py             # Main agent (run on target)
├── dns\_command\_gen.py   # Command generator for TXT records
├── server.py            # Flask-based result receiver
├── DATA/                # Result storage (auto-created)
├── README.md

```

---

## 🚀 Deployment Options

### 🖥️ Local Testing
- Run the Flask server with `python server.py`.
- Use tools like `playit.gg` or Cloudflare Tunnel to expose the server online.

### 🌐 VPS Hosting (Recommended)
- Host the Flask app using `gunicorn` + `nginx` or `Docker`.

### 💡 DNS Hosting
- Free DNS providers like `dynu.com` support custom TXT records.
- Minimum TTL of 30s helps reduce command delivery delay.

---

## 🔐 Encryption Details

- **Algorithm:** AES-128-CBC
- **Key/IV:** Hardcoded (must match across agent and command generator)
- **Padding:** Manual PKCS#7

---

## 📖 Learn More

Dive deeper into this project, its architecture, encryption logic, command structure, and practical usage in the full blog post:

🔗 [Read the full blog here](https://dkydivyansh.com/custom-c2-server-with-encrypted-dns-and-https-channels/)

---

## 🛑 Legal Disclaimer

This code is provided **strictly for educational purposes** and lawful cybersecurity research. Misuse may result in criminal charges. You are solely responsible for your actions.

---
