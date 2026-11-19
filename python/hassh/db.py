# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Lookup of fingerprints in the database shipped under hasshGen/."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

CLIENT_DB = "hassh_fingerprints.json"
SERVER_DB = "hasshserver_fingerprints.json"


def _db_dir() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here / "data", here.parent / "hasshGen"):
        if (candidate / CLIENT_DB).exists():
            return candidate
    return here / "data"


def load(filename: str) -> list[dict]:
    """Load a JSON-lines fingerprint database; missing files are empty."""
    path = _db_dir() / filename
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@cache
def _index(server: bool) -> dict[str, list[str]]:
    key, ident = ("hasshServer", "serverIdentificationString") if server else ("hassh", "clientIdentificationString")
    index: dict[str, list[str]] = {}
    for row in load(SERVER_DB if server else CLIENT_DB):
        names = index.setdefault(row[key], [])
        if row.get(ident) and row[ident] not in names:
            names.append(row[ident])
    return index


def lookup(fingerprint: str, *, server: bool = False) -> list[str]:
    """Identification strings known to produce *fingerprint*."""
    return list(_index(server).get(fingerprint, ()))
