#!/usr/bin/env python
"""Minimal paramiko SSH server (the building block of many honeypots)."""

import socket
import sys
import threading

import paramiko

port = int(sys.argv[1]) if len(sys.argv) > 1 else 22
host_key = paramiko.RSAKey.generate(2048)


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


def handle(conn):
    transport = paramiko.Transport(conn)
    transport.add_server_key(host_key)
    try:
        transport.start_server(server=Server())
        transport.join(10)
    except Exception as exc:
        print("connection ended: %r" % (exc,))
    finally:
        transport.close()


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", port))
listener.listen(16)
print("listening on %d" % port, flush=True)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
