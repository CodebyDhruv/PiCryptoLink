import json
import os
import signal
import threading
from queue import Queue, Empty
from typing import Optional

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

from tcp_server import TcpServer
from crypto import AesGcmCipher


app = Flask(__name__, static_folder="web/static", template_folder="web/templates")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "change-me")
# Use gevent for better memory efficiency on Pi
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent", logger=False, engineio_logger=False)


# Shared state
event_log_queue: "Queue[str]" = Queue()
tcp_server: Optional[TcpServer] = None
cipher: Optional[AesGcmCipher] = None


def log_event(message: str) -> None:
    event_log_queue.put(message)
    socketio.emit("log", {"message": message})


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/configure")
def configure():
    global cipher
    data = request.get_json(force=True, silent=True) or {}
    passphrase = data.get("passphrase", "")
    if not passphrase:
        return {"ok": False, "error": "Missing passphrase"}, 400
    cipher = AesGcmCipher.from_passphrase(passphrase)
    log_event("Configured encryption with new passphrase.")
    return {"ok": True}


@app.post("/send")
def send_message():
    global tcp_server, cipher
    data = request.get_json(force=True, silent=True) or {}
    plaintext = data.get("message", "")
    if not plaintext:
        return {"ok": False, "error": "Message required"}, 400
    if cipher is None:
        return {"ok": False, "error": "Cipher not configured"}, 400
    if tcp_server is None or not tcp_server.has_client():
        return {"ok": False, "error": "ESP32 not connected"}, 503

    encrypted = cipher.encrypt_to_json(plaintext.encode("utf-8"))

    try:
        tcp_server.send_json(encrypted)
        log_event(f"Pi Sent: {plaintext}")
        # Show proper JSON format in logs
        import json
        log_event(f"Ciphertext: {json.dumps(encrypted)}")
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        log_event(f"Send failed: {exc}")
        return {"ok": False, "error": str(exc)}, 500


@app.post("/esp32-status")
def esp32_status():
    """Receive status updates from ESP32"""
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "")
    status_type = data.get("type", "info")
    
    if message:
        if status_type == "decrypted":
            log_event(f"ESP32 Decrypted: {message}")
        elif status_type == "error":
            log_event(f"ESP32 Error: {message}")
        else:
            log_event(f"ESP32: {message}")
    
    return {"ok": True}


@socketio.on("connect")
def handle_connect():
    emit("log", {"message": "Web client connected."})


def start_tcp_server(host: str, port: int) -> TcpServer:
    server = TcpServer(host, port, on_client_connect=lambda addr: log_event(f"ESP32 connected: {addr}"),
                       on_client_disconnect=lambda addr: log_event(f"ESP32 disconnected: {addr}"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> None:
    global tcp_server
    host = os.environ.get("TCP_HOST", "0.0.0.0")
    port = int(os.environ.get("TCP_PORT", "5001"))
    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "5000"))

    tcp_server = start_tcp_server(host, port)
    log_event(f"TCP server listening on {host}:{port}")

    def handle_sigterm(_signum, _frame):
        if tcp_server:
            tcp_server.shutdown()
        os._exit(0)  # noqa: SLF001

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    socketio.run(app, host=web_host, port=web_port, debug=False)


if __name__ == "__main__":
    main()
