# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Dependency-free pcap / pcapng reader and TCP flow tracker.

Only what is needed to find SSH identification strings and KEXINIT messages:
Ethernet (with VLAN tags), Linux cooked v1/v2, BSD loopback and raw IP link
types; IPv4 and IPv6; in-order TCP reassembly of the first bytes of a flow.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import BinaryIO

from .kexinit import KexInit
from .stream import NotSSH, SSHStreamParser

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)

# IPv6 extension headers that may precede TCP.
_IPV6_EXT = {0, 43, 60, 135, 139, 140}

MAX_FLOWS = 100_000
MAX_PENDING_SEGMENTS = 64


class PcapError(ValueError):
    pass


# --------------------------------------------------------------------------
# capture file readers
# --------------------------------------------------------------------------
def _read_exact(fh: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes; b'' on clean EOF, short data is treated as EOF."""
    chunks = []
    remaining = n
    while remaining:
        chunk = fh.read(remaining)
        if not chunk:
            return b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_packets(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame) from a pcap or pcapng stream."""
    magic = _read_exact(fh, 4)
    if not magic:
        return
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(fh)
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        yield from _read_pcap(fh, "<", nano=magic[0] == 0x4D)
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        yield from _read_pcap(fh, ">", nano=magic[3] == 0x4D)
    else:
        raise PcapError("not a pcap or pcapng capture")


def _read_pcap(fh: BinaryIO, endian: str, nano: bool) -> Iterator[tuple[float, int, bytes]]:
    header = _read_exact(fh, 20)
    if len(header) < 20:
        raise PcapError("truncated pcap header")
    linktype = struct.unpack(endian + "I", header[16:20])[0] & 0x0FFFFFFF
    divisor = 1e9 if nano else 1e6
    while True:
        record = _read_exact(fh, 16)
        if len(record) < 16:
            return
        sec, frac, caplen, _ = struct.unpack(endian + "IIII", record)
        data = _read_exact(fh, caplen)
        if len(data) < caplen:
            return
        yield sec + frac / divisor, linktype, data


def _read_pcapng(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    block_type = 0x0A0D0D0A
    first = True
    while True:
        if not first:
            head = _read_exact(fh, 4)
            if len(head) < 4:
                return
            block_type = struct.unpack(endian + "I", head)[0]
        first = False
        raw_len = _read_exact(fh, 4)
        if len(raw_len) < 4:
            return
        if block_type == 0x0A0D0D0A:
            bom = _read_exact(fh, 4)
            if len(bom) < 4:
                return
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            total = struct.unpack(endian + "I", raw_len)[0]
            body = bom + _read_exact(fh, total - 12)
            interfaces = []
        else:
            total = struct.unpack(endian + "I", raw_len)[0]
            if total < 12:
                raise PcapError("corrupt pcapng block")
            body = _read_exact(fh, total - 8)
        if len(body) < total - 8:
            return
        body = body[:-4]  # trailing copy of the block length
        if block_type == 1:  # interface description
            linktype = struct.unpack_from(endian + "H", body)[0]
            interfaces.append((linktype, _if_resolution(body[8:], endian)))
        elif block_type == 6:  # enhanced packet
            iface, ts_hi, ts_lo, caplen = struct.unpack_from(endian + "IIII", body)
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (1, 1e-6)
            yield ((ts_hi << 32) | ts_lo) * tick, linktype, body[20 : 20 + caplen]
        elif block_type == 3 and interfaces:  # simple packet
            yield 0.0, interfaces[0][0], body[4:]


def _if_resolution(options: bytes, endian: str) -> float:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        offset += 4
        if code == 0:
            break
        if code == 9 and length >= 1:  # if_tsresol
            value = options[offset]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0**-value
        offset += (length + 3) & ~3
    return 1e-6


# --------------------------------------------------------------------------
# frame decoding
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Segment:
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    flags: int
    payload: bytes


def decode_frame(linktype: int, frame: bytes) -> Segment | None:
    """Decode a captured frame down to its TCP segment, or None."""
    try:
        if linktype == LINKTYPE_ETHERNET:
            ethertype = struct.unpack_from(">H", frame, 12)[0]
            offset = 14
            while ethertype in ETH_VLAN:
                ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
                offset += 4
        elif linktype == LINKTYPE_LINUX_SLL:
            ethertype = struct.unpack_from(">H", frame, 14)[0]
            offset = 16
        elif linktype == LINKTYPE_LINUX_SLL2:
            ethertype = struct.unpack_from(">H", frame, 0)[0]
            offset = 20
        elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
            offset = 4
            ethertype = 0
        elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
            offset = 0
            ethertype = 0
        else:
            return None
        if ethertype == 0:
            version = frame[offset] >> 4
            ethertype = ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else -1
        if ethertype == ETH_IPV4:
            return _decode_ipv4(frame, offset)
        if ethertype == ETH_IPV6:
            return _decode_ipv6(frame, offset)
    except (struct.error, IndexError):
        pass
    return None


def _decode_ipv4(frame: bytes, offset: int) -> Segment | None:
    ihl = (frame[offset] & 0x0F) * 4
    total_length, _, frag = struct.unpack_from(">HHH", frame, offset + 2)
    if frame[offset + 9] != 6 or frag & 0x3FFF:  # not TCP, or a fragment
        return None
    src = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
    dst = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
    end = offset + total_length if total_length else len(frame)  # 0 with TSO
    return _decode_tcp(frame, offset + ihl, min(end, len(frame)), src, dst)


def _decode_ipv6(frame: bytes, offset: int) -> Segment | None:
    payload_length = struct.unpack_from(">H", frame, offset + 4)[0]
    next_header = frame[offset + 6]
    src = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
    dst = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
    cursor = offset + 40
    end = cursor + payload_length if payload_length else len(frame)
    while next_header in _IPV6_EXT:
        next_header, ext_len = frame[cursor], frame[cursor + 1]
        cursor += (ext_len + 1) * 8
    if next_header != 6:
        return None
    return _decode_tcp(frame, cursor, min(end, len(frame)), src, dst)


def _decode_tcp(frame: bytes, offset: int, end: int, src: str, dst: str) -> Segment:
    sport, dport, seq, _, off_flags = struct.unpack_from(">HHIIH", frame, offset)
    data_offset = (off_flags >> 12) * 4
    return Segment(src, dst, sport, dport, seq, off_flags & 0x1FF, frame[offset + data_offset : end])


# --------------------------------------------------------------------------
# flow tracking
# --------------------------------------------------------------------------
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


@dataclass
class KexInitEvent:
    """A KEXINIT observed on the wire."""

    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    is_client: bool
    banner: str | None
    kexinit: KexInit

    @property
    def iso_timestamp(self) -> str:
        return datetime.fromtimestamp(self.timestamp, timezone.utc).replace(tzinfo=None).isoformat()


class _Flow:
    __slots__ = ("parser", "next_seq", "pending", "is_client", "dead")

    def __init__(self) -> None:
        self.parser = SSHStreamParser()
        self.next_seq: int | None = None
        self.pending: dict[int, bytes] = {}
        self.is_client: bool | None = None
        self.dead = False


class FlowTracker:
    """Feeds TCP segments into per-direction SSH stream parsers."""

    def __init__(self, max_flows: int = MAX_FLOWS) -> None:
        self._flows: OrderedDict[tuple[str, int, str, int], _Flow] = OrderedDict()
        self._max_flows = max_flows

    def _flow(self, key: tuple[str, int, str, int]) -> _Flow:
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = _Flow()
            if len(self._flows) > self._max_flows:
                self._flows.popitem(last=False)
        else:
            self._flows.move_to_end(key)
        return flow

    def add(self, timestamp: float, seg: Segment) -> KexInitEvent | None:
        key = (seg.src, seg.sport, seg.dst, seg.dport)
        if seg.flags & TCP_SYN:
            # A (re)used 4-tuple starts a fresh flow; the SYN tells us who the
            # client is and where the byte stream begins.
            flow = self._flows[key] = _Flow()
            self._flows.move_to_end(key)
            flow.next_seq = (seg.seq + 1) & 0xFFFFFFFF
            flow.is_client = not seg.flags & TCP_ACK
            return None
        if not seg.payload:
            return None
        flow = self._flow(key)
        if flow.dead:
            return None
        if flow.next_seq is None:  # capture started mid-handshake
            flow.next_seq = seg.seq
        kexinit = None
        try:
            for chunk in self._reassemble(flow, seg):
                kexinit = flow.parser.feed(chunk) or kexinit
        except NotSSH:
            flow.dead = True
            flow.pending.clear()
            return None
        if kexinit is None:
            return None
        flow.dead = True
        flow.pending.clear()
        is_client = flow.is_client
        if is_client is None:
            # No handshake seen: fall back to the original port heuristic.
            is_client = seg.sport > seg.dport
        return KexInitEvent(timestamp, seg.src, seg.dst, seg.sport, seg.dport, is_client, flow.parser.banner, kexinit)

    @staticmethod
    def _reassemble(flow: _Flow, seg: Segment) -> Iterator[bytes]:
        assert flow.next_seq is not None
        delta = (seg.seq - flow.next_seq) & 0xFFFFFFFF
        if delta >= 0x80000000:  # starts before next_seq: retransmission/overlap
            overlap = 0x100000000 - delta
            if overlap >= len(seg.payload):
                return
            data, delta = seg.payload[overlap:], 0
        else:
            data = seg.payload
        if delta:
            if len(flow.pending) < MAX_PENDING_SEGMENTS:
                flow.pending.setdefault(seg.seq, data)
            return
        while True:
            yield data
            flow.next_seq = (flow.next_seq + len(data)) & 0xFFFFFFFF
            data = flow.pending.pop(flow.next_seq, b"")
            if not data:
                return


def iter_kexinit(fh: BinaryIO) -> Iterator[KexInitEvent]:
    """Yield every KEXINIT found in a pcap / pcapng stream."""
    tracker = FlowTracker()
    for timestamp, linktype, frame in read_packets(fh):
        seg = decode_frame(linktype, frame)
        if seg is None:
            continue
        event = tracker.add(timestamp, seg)
        if event is not None:
            yield event
