#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Add hasshServer fingerprints that are only known from real-world scans.

The lab (hasshgen.py) cannot build everything: network equipment, firmware,
Windows and BSD builds, and every locally edited sshd_config. This script
takes scan observations and writes the fingerprints the lab does not have to
hasshserver_observed.json / .csv, labelled with the identification strings
the hosts presenting them announce.

The observations file is a JSON array of objects with the keys

  banner        identification string
  hassh_server  fingerprint
  algos         the hasshServer algorithm string (checked against the hash)
  ips           number of hosts
  nets          number of distinct networks (e.g. /16 prefixes) of those hosts
  day           optional; with several days a fingerprint must appear in all

An identification string is only published for a fingerprint when it was
seen on at least --min-nets networks, so that a banner customised by a
single organisation never ends up in the database. No host counts are
written, only a coarse prevalence class.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BANNER = re.compile(r"^SSH-[12]\.[0-9]+-[\x21-\x7e]{1,64}$")
COLUMNS = [
    "serverIdentificationString",
    "alsoSeenAs",
    "hasshServer",
    "hasshVersion",
    "hasshServerAlgorithms",
    "prevalence",
]


def version_token(identification: str) -> str:
    return identification.split(" ")[0].strip()


def prevalence(share: float) -> str:
    """Coarse class of the share of all scanned hosts."""
    if share >= 1e-3:
        return "common"
    if share >= 1e-4:
        return "uncommon"
    return "rare"


def harvest(
    rows: list[dict], known: set[str], min_hosts: int, min_nets: int, min_share: float
) -> tuple[list[dict], dict]:
    days = sorted({row.get("day", "") for row in rows})
    latest = days[-1]
    hosts: dict[str, Counter] = defaultdict(Counter)  # fingerprint -> day -> hosts
    banners: dict[str, Counter] = defaultdict(Counter)  # fingerprint -> banner -> hosts (latest day)
    nets: dict[tuple[str, str], int] = {}
    algos: dict[str, str] = {}
    total = 0
    for row in rows:
        fingerprint, banner, n = row.get("hassh_server") or "", row.get("banner") or "", int(row["ips"])
        day = row.get("day", "")
        if day == latest:
            total += n
        if not fingerprint or not row.get("algos"):
            continue
        hosts[fingerprint][day] += n
        algos[fingerprint] = row["algos"]
        if day == latest and BANNER.match(version_token(banner)):
            token = version_token(banner)
            banners[fingerprint][token] += n
            nets[fingerprint, token] = nets.get((fingerprint, token), 0) + int(row.get("nets", 0))

    out = []
    for fingerprint, per_day in hosts.items():
        if fingerprint in known or per_day[latest] < min_hosts or any(per_day[day] == 0 for day in days):
            continue
        if hashlib.md5(algos[fingerprint].encode(), usedforsecurity=False).hexdigest() != fingerprint:
            continue
        seen = sum(banners[fingerprint].values())
        names = [
            banner
            for banner, n in banners[fingerprint].most_common()
            if nets[fingerprint, banner] >= min_nets and n >= min_share * seen
        ]
        if not names:
            continue
        kex, enc, mac, cmp = (algos[fingerprint].split(";") + [""] * 4)[:4]
        out.append(
            {
                "serverIdentificationString": names[0],
                "alsoSeenAs": names[1:6],
                "hasshServer": fingerprint,
                "hasshServerAlgorithms": algos[fingerprint],
                "hasshVersion": "1.0",
                "skex": kex, "seastc": enc, "smastc": mac, "scastc": cmp,
                "prevalence": prevalence(per_day[latest] / total),
                "source": "observed",
                "_hosts": per_day[latest],
            }
        )  # fmt: skip
    out.sort(key=lambda row: (-row["_hosts"], row["hasshServer"]))
    all_hosts = sum(per_day[latest] for per_day in hosts.values())
    stats = {
        "hosts": total,
        "lab": sum(per_day[latest] for fp, per_day in hosts.items() if fp in known) / total,
        "observed": sum(row["_hosts"] for row in out) / total,
        "fingerprints": len(hosts),
        "with_fingerprint": all_hosts / total,
    }
    for row in out:
        del row["_hosts"]
    return out, stats


def write(base: Path, rows: list[dict]) -> None:
    with base.with_suffix(".json").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    with base.with_suffix(".csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(COLUMNS)
        for row in rows:
            writer.writerow([" ".join(row[c]) if isinstance(row[c], list) else row[c] for c in COLUMNS])


def prune(base: Path, known: set[str]) -> int:
    """Drop observed rows whose fingerprint the lab database has since learned."""
    path = base.with_suffix(".json")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    kept = [row for row in rows if row["hasshServer"] not in known]
    if len(kept) != len(rows):
        write(base, kept)
    return len(rows) - len(kept)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "observations", nargs="?", help="JSON file with banner / hassh_server / algos / ips / nets rows"
    )
    parser.add_argument("--prune", action="store_true", help="only remove rows the lab database now covers")
    parser.add_argument("--db", default=str(HERE / "hasshserver_fingerprints.json"), help="lab database")
    parser.add_argument("--out", default=str(HERE / "hasshserver_observed"), help="output base name")
    parser.add_argument("--min-hosts", type=int, default=20, help="hosts a fingerprint needs. Default: 20")
    parser.add_argument("--min-nets", type=int, default=10, help="networks an identification string needs. Default: 10")
    parser.add_argument("--min-share", type=float, default=0.1, help="share of a fingerprint's hosts a string needs")
    parser.add_argument("--days", help="comma-separated days to use; default: all in the file")
    parser.add_argument("--dry-run", action="store_true", help="print the statistics only")
    args = parser.parse_args()

    known = {json.loads(line)["hasshServer"] for line in Path(args.db).read_text().splitlines() if line.strip()}
    if args.prune:
        print(f"{prune(Path(args.out), known)} observed fingerprints are now in the lab database")
        return 0
    if not args.observations:
        parser.error("an observations file is required unless --prune is given")
    rows = json.loads(Path(args.observations).read_text())
    if args.days:
        rows = [row for row in rows if row.get("day") in args.days.split(",")]
    out, stats = harvest(rows, known, args.min_hosts, args.min_nets, args.min_share)
    if not args.dry_run:
        write(Path(args.out), out)
    print(f"{stats['fingerprints']} distinct fingerprints observed")
    print(f"lab database       : {100 * stats['lab']:.1f}% of hosts")
    print(f"observed, {len(out):5} new: {100 * stats['observed']:.1f}% of hosts")
    print(f"together           : {100 * (stats['lab'] + stats['observed']):.1f}% of hosts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
