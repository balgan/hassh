# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Parsing of SSH_MSG_KEXINIT (RFC 4253 section 7.1) and HASSH computation.

hassh       = md5(kex;enc_client_to_server;mac_client_to_server;comp_client_to_server)
hasshServer = md5(kex;enc_server_to_client;mac_server_to_client;comp_server_to_client)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import md5

HASSH_VERSION = "1.0"
SSH_MSG_KEXINIT = 20

# Upper bound from RFC 4253 section 6.1 is 35000 bytes for the whole packet,
# but several implementations accept more. Anything above this is not a
# plausible cleartext KEXINIT.
MAX_PACKET_LENGTH = 256 * 1024

_NAME_LIST_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


class KexInitError(ValueError):
    """Raised when a buffer does not hold a valid SSH_MSG_KEXINIT."""


def hassh_digest(algorithms: str) -> str:
    """MD5 of a hasshAlgorithms / hasshServerAlgorithms string.

    MD5 is used as a compact identifier, exactly as in JA3; it is not a
    security control.
    """
    return md5(algorithms.encode("utf-8", "surrogateescape"), usedforsecurity=False).hexdigest()


@dataclass(frozen=True)
class KexInit:
    """The ten name-lists of an SSH_MSG_KEXINIT message, as sent on the wire."""

    kex_algorithms: str
    server_host_key_algorithms: str
    encryption_algorithms_client_to_server: str
    encryption_algorithms_server_to_client: str
    mac_algorithms_client_to_server: str
    mac_algorithms_server_to_client: str
    compression_algorithms_client_to_server: str
    compression_algorithms_server_to_client: str
    languages_client_to_server: str
    languages_server_to_client: str
    first_kex_packet_follows: bool = False

    @property
    def hassh_algorithms(self) -> str:
        """Client fingerprint input: KEX;EACTS;MACTS;CACTS."""
        return ";".join(
            (
                self.kex_algorithms,
                self.encryption_algorithms_client_to_server,
                self.mac_algorithms_client_to_server,
                self.compression_algorithms_client_to_server,
            )
        )

    @property
    def hassh(self) -> str:
        return hassh_digest(self.hassh_algorithms)

    @property
    def hassh_server_algorithms(self) -> str:
        """Server fingerprint input: KEX;EASTC;MASTC;CASTC."""
        return ";".join(
            (
                self.kex_algorithms,
                self.encryption_algorithms_server_to_client,
                self.mac_algorithms_server_to_client,
                self.compression_algorithms_server_to_client,
            )
        )

    @property
    def hassh_server(self) -> str:
        return hassh_digest(self.hassh_server_algorithms)


def parse_name_lists(payload: bytes) -> KexInit:
    """Parse a KEXINIT *payload* (starting at the message code byte)."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise KexInitError("not an SSH_MSG_KEXINIT payload")
    offset = 1 + 16  # message code + cookie
    lists = []
    for name in _NAME_LIST_FIELDS:
        if offset + 4 > len(payload):
            raise KexInitError(f"truncated before {name}")
        (length,) = struct.unpack_from(">I", payload, offset)
        offset += 4
        if offset + length > len(payload):
            raise KexInitError(f"truncated inside {name}")
        lists.append(payload[offset : offset + length].decode("utf-8", "surrogateescape"))
        offset += length
    follows = offset < len(payload) and payload[offset] != 0
    return KexInit(*lists, first_kex_packet_follows=follows)


def packet_length(buf: bytes) -> int | None:
    """Total on-wire size of the cleartext binary packet at the start of *buf*.

    Returns None when fewer than four bytes are available. Raises KexInitError
    when the length field is implausible.
    """
    if len(buf) < 4:
        return None
    (length,) = struct.unpack_from(">I", buf)
    if length < 2 or length > MAX_PACKET_LENGTH:
        raise KexInitError(f"implausible packet length {length}")
    return 4 + length


def parse_kexinit(packet: bytes) -> KexInit:
    """Parse a complete cleartext SSH binary packet holding a KEXINIT."""
    total = packet_length(packet)
    if total is None or len(packet) < total:
        raise KexInitError("incomplete packet")
    padding = packet[4]
    payload = packet[5 : total - padding]
    return parse_name_lists(payload)


def build_kexinit(
    kex: str,
    host_key: str,
    enc: str,
    mac: str,
    comp: str = "none",
    *,
    cookie: bytes = b"\0" * 16,
) -> bytes:
    """Build a cleartext KEXINIT binary packet (same lists in both directions)."""
    payload = bytes([SSH_MSG_KEXINIT]) + cookie
    for value in (kex, host_key, enc, enc, mac, mac, comp, comp, "", ""):
        raw = value.encode()
        payload += struct.pack(">I", len(raw)) + raw
    payload += b"\0" + b"\0\0\0\0"  # first_kex_packet_follows, reserved
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return struct.pack(">IB", len(payload) + padding + 1, padding) + payload + b"\0" * padding
