# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Command line interface: extract HASSH fingerprints from capture files,
live traffic, or by actively probing servers / listening for clients."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, TextIO

from . import __version__, db
from .kexinit import HASSH_VERSION
from .net import probe, serve
from .pcap import KexInitEvent, PcapError, iter_kexinit
from .stream import NotSSH

CAP_BPF_FILTER = "tcp port 22 or tcp port 2222"

CSV_HEADER = (
    "timestamp,sourceIp,destinationIp,sourcePort,destinationPort,hasshType,"
    "identificationString,hassh,hasshVersion,hasshAlgorithms,kexAlgs,encAlgs,"
    "macAlgs,cmpAlgs"
)


class Color:
    CL1 = "\u001b[38;5;81m"
    CL2 = "\u001b[38;5;220m"
    CL3 = "\u001b[38;5;181m"
    CL4 = "\u001b[38;5;208m"
    END = "\033[0m"


def to_record(event: KexInitEvent) -> dict:
    """The JSON record for an event; field names match hassh.py 1.x."""
    k = event.kexinit
    record: dict = {
        "timestamp": event.iso_timestamp,
        "sourceIp": event.src,
        "destinationIp": event.dst,
        "sourcePort": str(event.sport),
        "destinationPort": str(event.dport),
    }
    if event.is_client:
        record.update(
            client=event.banner,
            hassh=k.hassh,
            hasshAlgorithms=k.hassh_algorithms,
            hasshVersion=HASSH_VERSION,
            ckex=k.kex_algorithms,
            ceacts=k.encryption_algorithms_client_to_server,
            cmacts=k.mac_algorithms_client_to_server,
            ccacts=k.compression_algorithms_client_to_server,
            clcts=k.languages_client_to_server,
            clstc=k.languages_server_to_client,
            ceastc=k.encryption_algorithms_server_to_client,
            cmastc=k.mac_algorithms_server_to_client,
            ccastc=k.compression_algorithms_server_to_client,
            cshka=k.server_host_key_algorithms,
        )
    else:
        record.update(
            server=event.banner,
            hasshServer=k.hassh_server,
            hasshServerAlgorithms=k.hassh_server_algorithms,
            hasshVersion=HASSH_VERSION,
            skex=k.kex_algorithms,
            seastc=k.encryption_algorithms_server_to_client,
            smastc=k.mac_algorithms_server_to_client,
            scastc=k.compression_algorithms_server_to_client,
            slcts=k.languages_client_to_server,
            slstc=k.languages_server_to_client,
            seacts=k.encryption_algorithms_client_to_server,
            smacts=k.mac_algorithms_client_to_server,
            scacts=k.compression_algorithms_client_to_server,
            sshka=k.server_host_key_algorithms,
        )
    return record


def to_csv(record: dict) -> str:
    if "hassh" in record:
        row = ["client", record["client"], record["hassh"], HASSH_VERSION, record["hasshAlgorithms"]]
        row += [record["ckex"], record["ceacts"], record["cmacts"], record["ccacts"]]
    else:
        row = ["server", record["server"], record["hasshServer"], HASSH_VERSION, record["hasshServerAlgorithms"]]
        row += [record["skex"], record["seastc"], record["smastc"], record["scastc"]]
    head = [record[k] for k in ("timestamp", "sourceIp", "destinationIp", "sourcePort", "destinationPort")]
    out = io.StringIO()
    csv.writer(out, lineterminator="").writerow(head + ["" if v is None else v for v in row])
    return out.getvalue()


def to_text(record: dict, color: bool, known: list[str]) -> str:
    c = Color if color else type("NoColor", (), dict.fromkeys(("CL1", "CL2", "CL3", "CL4", "END"), ""))
    client = "hassh" in record
    hi = c.CL2 if client else c.CL4
    name = "hassh" if client else "hasshServer"
    lines = [
        f"[+] {'Client' if client else 'Server'} SSH_MSG_KEXINIT detected",
        f"    {c.CL1}[ {record['sourceIp']}:{record['sourcePort']} -> "
        f"{record['destinationIp']}:{record['destinationPort']} ]{c.END}",
        f"        [-] Identification String: {hi}{record['client' if client else 'server']}{c.END}",
        f"        [-] {name}: {hi}{record[name]}{c.END}",
        f"        [-] {name} Algorithms: {c.CL3}{record[name + 'Algorithms']}{c.END}",
    ]
    if known:
        shown = ", ".join(known[:5]) + (f" (+{len(known) - 5} more)" if len(known) > 5 else "")
        lines.append(f"        [-] Known as: {c.CL3}{shown}{c.END}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# event sources
# --------------------------------------------------------------------------
def _pcap_events(path: Path) -> Iterator[KexInitEvent]:
    with path.open("rb") as fh:
        yield from iter_kexinit(fh)


def _directory_events(directory: Path) -> Iterator[KexInitEvent]:
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        try:
            yield from _pcap_events(path)
        except PcapError:
            print(f"[-] skipping {path}: not a capture file", file=sys.stderr)


def _live_events(interface: str, bpf: str, write_pcap: str | None) -> Iterator[KexInitEvent]:
    """Live capture through tcpdump, which hands us a pcap stream on stdout."""
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        raise SystemExit("[-] live capture needs tcpdump on the PATH")
    cmd = [tcpdump, "-i", interface, "-U", "-s", "0", "-w", "-", bpf]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    assert proc.stdout is not None
    stream: BinaryIO = proc.stdout
    try:
        if write_pcap:
            with open(write_pcap, "wb") as copy:
                yield from iter_kexinit(_Tee(stream, copy))  # type: ignore[arg-type]
        else:
            yield from iter_kexinit(stream)
    finally:
        proc.terminate()
        proc.wait()


class _Tee:
    def __init__(self, source: BinaryIO, copy: BinaryIO) -> None:
        self._source, self._copy = source, copy

    def read(self, n: int) -> bytes:
        data = self._source.read(n)
        self._copy.write(data)
        return data


def _parse_endpoint(value: str, default_port: int) -> tuple[str, int]:
    if value.startswith("["):  # [v6]:port
        host, _, rest = value[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if value.count(":") == 1:
        host, port = value.split(":")
        return host, int(port)
    return value, default_port


def _parse_listen(value: str) -> tuple[str, list[int]]:
    """[ADDR:]PORT or [ADDR:]FIRST-LAST"""
    host, _, ports = value.rpartition(":")
    first, _, last = ports.partition("-")
    return host.strip("[]") or "0.0.0.0", list(range(int(first), int(last or first) + 1))


def _probe_events(targets: Iterable[str], timeout: float) -> Iterator[KexInitEvent]:
    for target in targets:
        host, port = _parse_endpoint(target, 22)
        try:
            yield probe(host, port, timeout=timeout)
        except (OSError, NotSSH) as exc:
            print(f"[-] {target}: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hassh", description="Extract HASSH fingerprints of SSH clients and servers.")
    parser.add_argument("-V", "--version", action="version", version=f"hassh {__version__}")
    src = parser.add_argument_group("input (choose one)")
    src.add_argument("-r", "--read_file", help="pcap or pcapng file to process ('-' for stdin)")
    src.add_argument("-d", "--read_directory", help="directory of capture files to process")
    src.add_argument("-i", "--interface", help="listen on interface (uses tcpdump)")
    src.add_argument(
        "--probe", nargs="+", metavar="HOST[:PORT]", help="connect to SSH servers and print their hasshServer"
    )
    src.add_argument(
        "--listen",
        metavar="[ADDR:]PORT[-PORT]",
        help="accept SSH clients on a port or port range and print their hassh",
    )
    parser.add_argument(
        "-fp",
        "--fingerprint",
        default="all",
        choices=["client", "server", "all"],
        help="client or server fingerprint. Default: all",
    )
    parser.add_argument(
        "-f",
        "--bpf_filter",
        default=CAP_BPF_FILTER,
        help=f"BPF capture filter (live capture only). Default: '{CAP_BPF_FILTER}'",
    )
    parser.add_argument("-l", "--log_format", choices=["json", "csv"], help="output log format")
    parser.add_argument(
        "-o", "--output_file", default="hassh.log", help="output log file, '-' for stdout. Default: hassh.log"
    )
    parser.add_argument("-w", "--write_pcap", help="save the live captured packets to this file")
    parser.add_argument("-p", "--print_output", action="store_true", help="print the output")
    parser.add_argument("--count", type=int, help="with --listen: exit after this many clients")
    parser.add_argument("--timeout", type=float, default=10.0, help="socket timeout for --probe/--listen")
    parser.add_argument("--no-lookup", action="store_true", help="do not match against the fingerprint database")
    # Accepted for compatibility with hassh.py 1.x; SSH is now detected on any port.
    parser.add_argument("-da", "--decode_as", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.read_file == "-":
        events: Iterator[KexInitEvent] = iter_kexinit(sys.stdin.buffer)
    elif args.read_file:
        events = _pcap_events(Path(args.read_file))
    elif args.read_directory:
        events = _directory_events(Path(args.read_directory))
    elif args.interface:
        events = _live_events(args.interface, args.bpf_filter, args.write_pcap)
    elif args.probe:
        events = _probe_events(args.probe, args.timeout)
    elif args.listen:
        host, ports = _parse_listen(args.listen)
        events = serve(host, ports, count=args.count, timeout=args.timeout)
    else:
        parser.print_help()
        return 2

    print_output = args.print_output or not args.log_format
    log: TextIO | None = None
    if args.log_format:
        log = sys.stdout if args.output_file == "-" else open(args.output_file, "a", encoding="utf-8")
        if args.log_format == "csv":
            print(CSV_HEADER, file=log)
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    try:
        for event in events:
            if args.fingerprint != "all" and (args.fingerprint == "client") != event.is_client:
                continue
            record = to_record(event)
            if log is not None:
                print(json.dumps(record) if args.log_format == "json" else to_csv(record), file=log, flush=True)
            if print_output and log is not sys.stdout:
                known = (
                    []
                    if args.no_lookup
                    else db.lookup(record.get("hassh") or record["hasshServer"], server=not event.is_client)
                )
                print(to_text(record, color, known), flush=True)
    except PcapError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        if log is not None and log is not sys.stdout:
            log.close()
    return 0
