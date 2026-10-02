import socket
import threading

import pytest


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
