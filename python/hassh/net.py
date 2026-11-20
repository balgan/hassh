# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Active fingerprinting without packet capture.

probe()  connects to an SSH server and returns its KEXINIT (hasshServer).
serve()  accepts SSH clients and yields their KEXINIT (hassh).

Neither side ever completes a key exchange or authenticates.
"""

from __future__ import annotations

import contextlib
import selectors
import socket
import time
from collections.abc import Iterable, Iterator

from .kexinit import build_kexinit
from .pcap import KexInitEvent
from .stream import NotSSH, SSHStreamParser

# An identification string no implementation has compatibility quirks for, so
# the peer answers with its default algorithm proposal.
IDENTIFICATION = "SSH-2.0-hassh_2.0"

# A broad proposal so that clients which inspect the server's KEXINIT before
# sending their own still find something to agree on.
_SERVER_KEXINIT = build_kexinit(
    kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
    "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    host_key="ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-rsa,ssh-dss",
    enc="chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes128-cbc,3des-cbc",
    mac="hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    comp="none,zlib@openssh.com,zlib",
)


# Sent by probe() only to servers that wait for the client's KEXINIT before
# sending their own.
_CLIENT_KEXINIT = build_kexinit(
    kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
    "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
    "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    host_key="ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
    enc="chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,"
    "aes256-gcm@openssh.com,aes128-cbc,3des-cbc",
    mac="hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    comp="none,zlib@openssh.com",
)


def _read_kexinit(sock: socket.socket, parser: SSHStreamParser, nudge: bytes | None = None) -> None:
    """Read until the peer's KEXINIT is complete.

    Nearly every implementation sends its KEXINIT right after the
    identification string. A few wait for the other side's first: with
    *nudge*, that packet is sent once when the peer has identified itself and
    then stayed silent for half the socket timeout.
    """
    timeout = sock.gettimeout()
    if nudge and timeout:
        sock.settimeout(timeout / 2)
    while parser.kexinit is None:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            if not nudge or parser.banner is None:
                raise
            sock.sendall(nudge)
            nudge = None
            continue
        if not data:
            raise NotSSH("connection closed before SSH_MSG_KEXINIT")
        parser.feed(data)


def probe(host: str, port: int = 22, timeout: float = 10.0) -> KexInitEvent:
    """Fetch the server KEXINIT from host:port.

    Raises OSError on connection problems and NotSSH if the peer does not
    speak SSH.
    """
    parser = SSHStreamParser()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        local, remote = sock.getsockname(), sock.getpeername()
        sock.sendall(IDENTIFICATION.encode() + b"\r\n")
        _read_kexinit(sock, parser, _CLIENT_KEXINIT)
    assert parser.kexinit is not None
    return KexInitEvent(time.time(), remote[0], local[0], remote[1], local[1], False, parser.banner, parser.kexinit)


def serve(
    host: str = "0.0.0.0",
    ports: int | Iterable[int] = 2222,
    *,
    count: int | None = None,
    timeout: float = 10.0,
) -> Iterator[KexInitEvent]:
    """Listen for SSH clients and yield the KEXINIT of each one.

    *ports* may be a single port or several; listening on one port per client
    under test lets a single collector tell many concurrent clients apart by
    the destination port of the event. Stops after *count* fingerprints when
    given, otherwise runs forever.
    """
    if isinstance(ports, int):
        ports = [ports]
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with selectors.DefaultSelector() as selector, contextlib.ExitStack() as stack:
        for port in ports:
            listener = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
            listener.listen(64)
            selector.register(listener, selectors.EVENT_READ)
        seen = 0
        while count is None or seen < count:
            for key, _ in selector.select():
                event = _handle_client(key.fileobj, timeout)  # type: ignore[arg-type]
                if event is not None:
                    seen += 1
                    yield event


def _handle_client(listener: socket.socket, timeout: float) -> KexInitEvent | None:
    try:
        conn, peer = listener.accept()
    except OSError:
        return None
    parser = SSHStreamParser()
    with conn:
        conn.settimeout(timeout)
        local = conn.getsockname()
        try:
            conn.sendall(IDENTIFICATION.encode() + b"\r\n" + _SERVER_KEXINIT)
            _read_kexinit(conn, parser)
        except (OSError, NotSSH):
            return None
    assert parser.kexinit is not None
    return KexInitEvent(time.time(), peer[0], local[0], peer[1], local[1], True, parser.banner, parser.kexinit)
