#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Check lab-generated hasshServer fingerprints against real-world scans.

The observations file is a JSON array of objects with the keys
``banner`` (identification string), ``hassh_server`` and ``ips`` (number of
hosts), e.g. the result of grouping internet-wide SSH scan data by banner and
hasshServer. A lab fingerprint is

  confirmed  when hosts announcing the same software version present it,
  unseen     when no host announces that version (nothing to compare with),
  absent     when hosts announce that version but none presents the
             fingerprint - worth a look: either the build differs from what
             is deployed, or nobody runs that build with default settings.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent


def version_token(identification: str) -> str:
    """'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13' -> 'SSH-2.0-OpenSSH_9.6p1'"""
    return identification.split(" ")[0].strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("observations", help="JSON file with banner / hassh_server / ips rows")
    parser.add_argument("--db", default=str(HERE / "hasshserver_fingerprints.json"))
    parser.add_argument("--min-hosts", type=int, default=50, help="hosts needed before 'absent' is reported")
    parser.add_argument("--markdown", action="store_true", help="print a markdown table")
    parser.add_argument("--day", help="with several scans in the file: the one to use. Default: the latest")
    args = parser.parse_args()

    observed: dict[str, Counter] = defaultdict(Counter)
    by_hash: Counter = Counter()
    rows = json.loads(Path(args.observations).read_text())
    day = args.day or max(row.get("day", "") for row in rows)
    for row in rows:
        if row.get("day", "") != day:
            continue
        if row.get("banner") and row.get("hassh_server"):
            observed[version_token(row["banner"])][row["hassh_server"]] += int(row["ips"])
            by_hash[row["hassh_server"]] += int(row["ips"])

    # One line per distinct (version token, fingerprint) in the database.
    lab: dict[tuple[str, str], list[str]] = {}
    for line in Path(args.db).read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            key = (version_token(row["serverIdentificationString"]), row["hasshServer"])
            profile = f" [{row['configuration']}]" if row.get("configuration") else ""
            lab.setdefault(key, []).append(f"{row['image']}:{row['imageVersion']}{profile}")

    counts: Counter = Counter()
    lines = []
    for (token, fingerprint), sources in lab.items():
        seen = observed.get(token)
        total = sum(seen.values()) if seen else 0
        if seen and fingerprint in seen:
            rank = sorted(seen.values(), reverse=True).index(seen[fingerprint]) + 1
            status = "confirmed"
            share = 100 * seen[fingerprint] / total
            detail = f"{seen[fingerprint]} of {total} hosts ({share:.1f}%), rank {rank}"
            if args.markdown:  # shares only, no absolute numbers
                detail = f"{share:.1f}% of hosts announcing this version, rank {rank} of {len(seen)}"
        elif total >= args.min_hosts:
            status = "absent"
            top, top_hosts = seen.most_common(1)[0]
            detail = f"0 of {total} hosts; most common there is {top} ({top_hosts})"
            if args.markdown:
                detail = f"not seen; hosts announcing this version present {top}"
        else:
            status = "unseen"
            detail = f"only {total} hosts announce this version"
            if args.markdown:
                detail = "too few hosts announce this version"
        if status != "confirmed" and by_hash[fingerprint] and not args.markdown:
            detail += f"; fingerprint seen on {by_hash[fingerprint]} hosts under other banners"
        counts[status] += 1
        lines.append((status, token, fingerprint, detail, ", ".join(sorted(set(sources)))))

    if args.markdown:
        print("| status | identification | hasshServer | internet scan | lab source |")
        print("|---|---|---|---|---|")
        for line in sorted(lines):
            print("| " + " | ".join(line) + " |")
    else:
        for status, token, fingerprint, detail, sources in lines:
            print(f"{status:9} {token:34} {fingerprint}  {detail}  [{sources}]")
    print()
    print(", ".join(f"{n} {status}" for status, n in sorted(counts.items())), f"of {len(lines)} lab fingerprints")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
