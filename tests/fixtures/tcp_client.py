"""Test fixture: connects to 127.0.0.1:<port> (argv[1]) and holds the
connection open briefly, so a polling network observer has time to see it."""

import socket
import sys
import time

if __name__ == "__main__":
    port = int(sys.argv[1])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b"hello")
        time.sleep(2.0)
