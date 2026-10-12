import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import sys

collect_ignore_glob = []
if sys.platform != "win32":
    collect_ignore_glob = ["test_real_network.py", "test_flaky.py",
                           "test_load.py", "test_native.py"]

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep pytest output clean

    def _reply(self, status, body, ctype=None, headers=None):
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/error500":
            self._reply(500, b'Traceback (most recent call last):\n'
                             b'  File "app/handlers.py", line 42, in get_user\n'
                             b'    return users[user_id]\n'
                             b'KeyError: 42\n')
        elif self.path == "/partial":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "100")  # promises 100 bytes
            self.end_headers()
            self.wfile.write(b'{"items": [1, 2, 3')  # sends only 18, then closes
        elif self.path == "/slow":
            time.sleep(1)
            self._reply(200, b"ok")
        elif self.path == "/missing":
            self._reply(404, b"not found")
        elif self.path == "/unavailable":
            self._reply(503, b"upstream connection refused")
        elif self.path == "/wrongtype":
            self._reply(200, b'{"count": "5"}', "application/json")
        elif self.path == "/hang":
            time.sleep(5)  # the client gives up after 2 seconds
            try:
                self._reply(200, b"too late")
            except OSError:
                pass  # client already hung up
        elif self.path == "/unauthorized":
            self._reply(401, b"invalid token",
                        headers={"WWW-Authenticate": "Bearer"})
        elif self.path == "/ratelimited":
            self._reply(429, b"too many requests",
                        headers={"Retry-After": "30"})
        elif self.path == "/closeearly":
            self.close_connection = True  # read the request, send nothing, close

@pytest.fixture
def http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def reset_server():
    """Accepts a connection, then aborts it with a TCP RST."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn = srv.accept()[0]
            except OSError:
                continue
            # SO_LINGER with timeout 0 makes close() send RST instead of FIN
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
            conn.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield "127.0.0.1", srv.getsockname()[1]
    stop.set()
    t.join()
    srv.close()



@pytest.fixture
def listening_server():
    """A real TCP server that accepts connections but never replies."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))  # port 0 = OS picks a free port
    srv.listen(5)
    srv.settimeout(0.2)
    conns, stop = [], threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conns.append(srv.accept()[0])
            except OSError:
                pass  # accept timed out, loop again

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield "127.0.0.1", srv.getsockname()[1]
    stop.set()
    t.join()
    for c in conns:
        c.close()
    srv.close()


@pytest.fixture
def closed_port():
    """A port that was free a moment ago and has nothing listening."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return "127.0.0.1", port
