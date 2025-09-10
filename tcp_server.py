import json
import socket
import threading
from typing import Callable, Optional


class TcpServer:
    def __init__(
        self,
        host: str,
        port: int,
        on_client_connect: Optional[Callable[[tuple[str, int]], None]] = None,
        on_client_disconnect: Optional[Callable[[tuple[str, int]], None]] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._on_client_connect = on_client_connect
        self._on_client_disconnect = on_client_disconnect
        self._server_socket: Optional[socket.socket] = None
        self._client_socket: Optional[socket.socket] = None
        self._client_addr: Optional[tuple[str, int]] = None
        self._shutdown = threading.Event()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self._host, self._port))
            srv.listen(1)
            self._server_socket = srv
            while not self._shutdown.is_set():
                try:
                    srv.settimeout(1.0)
                    client, addr = srv.accept()
                except socket.timeout:
                    continue
                self._client_socket = client
                self._client_addr = (addr[0], addr[1])
                if self._on_client_connect:
                    self._on_client_connect(self._client_addr)
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()

    def _handle_client(self, client: socket.socket, addr: tuple[str, int]) -> None:
        try:
            # One-way sender; just keep socket open until client disconnects
            client.settimeout(0.5)
            while not self._shutdown.is_set():
                try:
                    data = client.recv(1)
                    if not data:
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                client.close()
            except Exception:
                pass
            if self._on_client_disconnect and self._client_addr:
                self._on_client_disconnect(self._client_addr)
            self._client_socket = None
            self._client_addr = None

    def has_client(self) -> bool:
        return self._client_socket is not None

    def send_json(self, payload: dict) -> None:
        if not self._client_socket:
            raise RuntimeError("No client connected")
        line = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        self._client_socket.sendall(line)

    def shutdown(self) -> None:
        self._shutdown.set()
        try:
            if self._client_socket:
                self._client_socket.close()
        except Exception:
            pass
        try:
            if self._server_socket:
                self._server_socket.close()
        except Exception:
            pass