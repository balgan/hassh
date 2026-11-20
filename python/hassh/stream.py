# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Extract the identification string and KEXINIT from one direction of an
SSH byte stream (RFC 4253 sections 4.2 and 7.1)."""

from __future__ import annotations

from .kexinit import KexInit, KexInitError, packet_length, parse_kexinit

# SSH_MSG_IGNORE and SSH_MSG_DEBUG may be sent at any time (RFC 4253 section
# 11), also ahead of the KEXINIT. Skip at most this many of them.
_SKIPPABLE = (2, 4)
MAX_SKIPPED_PACKETS = 8

# A server may send other lines before its identification string, and the
# string itself is at most 255 bytes. Give up on streams that have not
# produced one within this many bytes.
MAX_PREAMBLE = 8192


class NotSSH(Exception):
    """The byte stream is not the start of an SSH connection."""


class SSHStreamParser:
    """Incremental parser fed with in-order bytes of one flow direction."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._preamble = 0
        self._skipped = 0
        self.banner: str | None = None
        self.kexinit: KexInit | None = None
        self.done = False

    def feed(self, data: bytes) -> KexInit | None:
        """Add bytes. Returns the KexInit once, when it becomes available.

        Raises NotSSH as soon as the stream is known not to be SSH.
        """
        if self.done:
            return None
        self._buf += data
        try:
            if self.banner is None and not self._read_banner():
                return None
            while True:
                total = packet_length(self._buf)
                if total is None or len(self._buf) < total:
                    return None
                if not self._skip(total):
                    break
            self.kexinit = parse_kexinit(bytes(self._buf[:total]))
        except KexInitError as exc:
            self._finish()
            raise NotSSH(str(exc)) from None
        self._finish()
        return self.kexinit

    def _skip(self, total: int) -> bool:
        """Drop a leading SSH_MSG_IGNORE / SSH_MSG_DEBUG packet."""
        if total < 6 or self._buf[5] not in _SKIPPABLE or self._skipped >= MAX_SKIPPED_PACKETS:
            return False
        self._skipped += 1
        del self._buf[:total]
        return True

    def _finish(self) -> None:
        self.done = True
        self._buf.clear()

    def _read_banner(self) -> bool:
        while True:
            end = self._buf.find(b"\n")
            if end < 0:
                if len(self._buf) > MAX_PREAMBLE or not self._plausible(self._buf):
                    raise KexInitError("no identification string")
                return False
            line = bytes(self._buf[:end]).rstrip(b"\r")
            del self._buf[: end + 1]
            self._preamble += end + 1
            if line.startswith(b"SSH-"):
                self.banner = line.decode("utf-8", "replace")
                return True
            if self._preamble > MAX_PREAMBLE or not self._plausible(line):
                raise KexInitError("no identification string")

    @staticmethod
    def _plausible(line: bytes) -> bool:
        """Pre-banner lines are text; reject binary protocols early."""
        head = line[:4]
        if b"SSH-".startswith(head) or head.startswith(b"SSH-"):
            return True
        return len(line) <= MAX_PREAMBLE and all(b >= 0x20 or b in (9, 13) for b in line[:64])
