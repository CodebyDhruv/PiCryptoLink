# Pi → ESP32 Secure One-Way Messaging (AES-256-GCM)

This project sends encrypted messages from a Raspberry Pi (server) to an ESP32 (client). Messages are encrypted on the Pi using AES-256-GCM and decrypted only on the ESP32. A Flask+Socket.IO web UI lets you configure the shared passphrase and send messages, with real-time logs.

## Topology
- Pi Zero 2W: runs Flask web UI (port 5000) + TCP server (port 5001)
- ESP32: connects to Pi's TCP server over Wi‑Fi, receives JSON lines: `{iv,ciphertext,tag}` (base64)

## Requirements (Pi)
```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m pip install -r requirements.txt
```

## Run (Pi)
```bash
export WEB_HOST=0.0.0.0 WEB_PORT=5000 TCP_HOST=0.0.0.0 TCP_PORT=5001
python3 server.py
```
Then open `http://<Pi-IP>:5000` in your browser.

## Web UI Flow
1) Enter a shared passphrase (same will be set on ESP32). This derives a 256-bit key via SHA-256.
2) Type a message and click Send. The Pi encrypts and sends JSON to the ESP32.
3) Logs show plaintext sent and ciphertext JSON; ESP32 serial shows decrypted plaintext.

## ESP32 (Arduino IDE)
- Copy `esp32/esp32_receiver/esp32_receiver.ino` into an Arduino sketch.
- Install libraries: ArduinoJson (via Library Manager).
- Board: ESP32 Dev Module.

Edit defaults at top of sketch or press Enter at boot to configure via Serial:
- Wi‑Fi SSID/PASS
- Pi IP/port
- Shared passphrase (must match what you set on the web UI)

Open Serial Monitor at 115200 baud to see logs.

## Message Format
```json
{"iv":"base64","ciphertext":"base64","tag":"base64"}
```
- IV is 12 bytes (96-bit), ciphertext/tag vary by message size (tag 16 bytes)

## Notes
- One-way only: Pi → ESP32. The ESP32 does not send data back.
- AES-256-GCM via PyCryptodome (Pi) and mbedTLS (ESP32). Key = SHA-256(passphrase).
- For production, prefer provisioning unique keys and TLS between devices.






