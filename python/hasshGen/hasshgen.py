#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Generate HASSH fingerprints for many SSH implementations with containers.

One long-lived *collector* container runs the hassh tool. Every SSH
implementation under test is built into its own image and started on the same
private Docker network:

  * servers are started and probed from the collector  -> hasshServer
  * clients connect to the collector, each to its own port -> hassh

Nothing listens on the host and no packet capture is needed.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCKERFILE_DIR = HERE / "dockerfiles"
WORK_DIR = HERE / ".hasshgen"
NETWORK = "hasshgen"
COLLECTOR = "hasshgen-collector"
COLLECTOR_IMAGE = "hasshgen/collector"
FIRST_PORT, LAST_PORT = 10000, 11999

CLIENT_DB = HERE / "hassh_fingerprints"
SERVER_DB = HERE / "hasshserver_fingerprints"

_SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"
# Distribution sshd: make sure host keys and runtime directories exist. RHEL 8
# passes its system-wide crypto policy on the sshd command line from the unit
# file, later releases include it from sshd_config.
_PKG_SSHD = (
    "ssh-keygen -A >/dev/null 2>&1; mkdir -p /run/sshd /var/run/sshd /var/empty/sshd; "
    "f=/etc/crypto-policies/back-ends/opensshserver.config; "
    "if grep -qs '^CRYPTO_POLICY=' $f; then . $f; fi; "
    "exec $(command -v sshd || echo /usr/sbin/sshd) -D -e -p 22 $CRYPTO_POLICY"
)
_PKG_SSH = f"ssh {_SSH_OPTS} -p $PORT hassh@$HOST true"
_DROPBEAR = "mkdir -p /etc/dropbear; exec $(command -v dropbear || echo /usr/sbin/dropbear) -F -E -R -p 22"
_DBCLIENT = "dbclient -y -p $PORT hassh@$HOST true </dev/null"

# recipe -> how to build, start and name an implementation.
#   client / server : shell commands run inside the image
#   names           : (sshClient, sshServer) values written to the database
#   version         : shell command printing the installed version; without it
#                     the "version" of the target is used
RECIPES: dict[str, dict] = {
    "openssh-src": {
        "dockerfile": "Dockerfile.openssh-src",
        "server": "exec /opt/openssh/sbin/sshd -D -e -p 22",
        "client": f"/opt/openssh/bin/ssh -F /dev/null {_SSH_OPTS} -p $PORT hassh@$HOST true",
        "names": ("openssh-portable", "openssh-portable"),
    },
    "dropbear-src": {
        "dockerfile": "Dockerfile.dropbear-src",
        "server": _DROPBEAR,
        "client": _DBCLIENT,
        "names": ("dropbear", "dropbear"),
    },
    "paramiko": {
        "dockerfile": "Dockerfile.paramiko",
        "server": "exec python /opt/paramiko_server.py 22",
        "client": "python /opt/paramiko_conn.py $HOST $PORT",
        "names": ("paramiko", "paramiko"),
    },
    "apk-openssh": {
        "dockerfile": "Dockerfile.alpine",
        "packages": "openssh",
        "version": "apk info -v 2>/dev/null | sed -n 's/^openssh-\\([0-9]\\)/\\1/p' | head -n1",
        "server": _PKG_SSHD,
        "client": _PKG_SSH,
        "names": ("openssh-client", "openssh-server"),
    },
    "apk-dropbear": {
        "dockerfile": "Dockerfile.alpine",
        "packages": "dropbear dropbear-dbclient",
        "version": "apk info -v 2>/dev/null | sed -n 's/^dropbear-\\([0-9]\\)/\\1/p' | head -n1",
        "server": _DROPBEAR,
        "client": _DBCLIENT,
        "names": ("dropbear-dbclient", "dropbear"),
    },
    "apt-openssh": {
        "dockerfile": "Dockerfile.debian",
        "packages": "openssh-client openssh-server",
        "version": "dpkg-query -W -f='${Version}' openssh-server",
        "server": _PKG_SSHD,
        "client": _PKG_SSH,
        "names": ("openssh-client", "openssh-server"),
    },
    "apt-dropbear": {
        "dockerfile": "Dockerfile.debian",
        "packages": "dropbear-bin",
        "version": "dpkg-query -W -f='${Version}' dropbear-bin",
        "server": _DROPBEAR,
        "client": _DBCLIENT,
        "names": ("dropbear", "dropbear"),
    },
    "rpm-openssh": {
        "dockerfile": "Dockerfile.rpm",
        "packages": "openssh-clients openssh-server",
        "version": "rpm -q --qf '%{VERSION}-%{RELEASE}' openssh-server",
        "server": _PKG_SSHD,
        "client": _PKG_SSH,
        "names": ("openssh-clients", "openssh-server"),
    },
    "zypper-openssh": {
        "dockerfile": "Dockerfile.rpm",
        "packages": "openssh",
        "version": "rpm -q --qf '%{VERSION}-%{RELEASE}' openssh",
        "server": _PKG_SSHD,
        "client": _PKG_SSH,
        "names": ("openssh", "openssh"),
    },
}

_lock = threading.Lock()
_next_port = FIRST_PORT


def docker(*args: str, timeout: float = 120, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        # Drop BuildKit's echo of the Dockerfile; keep what the failing command said.
        noise = re.compile(r"^\s*\d+ \||^-+$|^Dockerfile|^ERROR: failed to|^View build details|^$")
        tail = [line for line in lines if not noise.search(line)][-8:]
        raise RuntimeError(f"docker {args[0]} failed:\n" + "\n".join(tail))
    return proc


def slug(target: dict) -> str:
    parts = [target["recipe"], target["image"], target["image_ver"], target.get("version", "")]
    return re.sub(r"[^a-z0-9.]+", "-", "-".join(p for p in parts if p).lower()).strip("-")


# --------------------------------------------------------------------------
# collector
# --------------------------------------------------------------------------
def start_collector() -> None:
    docker("build", "-q", "-t", COLLECTOR_IMAGE, "-f", str(DOCKERFILE_DIR / "Dockerfile.collector"), str(HERE.parent))
    if docker("network", "inspect", NETWORK, check=False).returncode != 0:
        docker("network", "create", NETWORK)
    docker("rm", "-f", COLLECTOR, check=False)
    docker(
        "run", "-d", "--name", COLLECTOR, "--network", NETWORK, COLLECTOR_IMAGE,
        "--listen", f"0.0.0.0:{FIRST_PORT}-{LAST_PORT}", "-l", "json", "-o", "-",
    )  # fmt: skip


def stop_collector() -> None:
    docker("rm", "-f", COLLECTOR, check=False)
    docker("network", "rm", NETWORK, check=False)


def collector_client_record(port: int) -> dict | None:
    """The fingerprint of the client that connected to *port*, if any yet."""
    found = None
    for line in docker("logs", COLLECTOR).stdout.splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            if record.get("destinationPort") == str(port):
                found = record
    return found


# --------------------------------------------------------------------------
# one target
# --------------------------------------------------------------------------
def build(target: dict, tag: str) -> None:
    recipe = RECIPES[target["recipe"]]
    cmd = ["build", "--progress=plain", "-t", tag, "-f", str(DOCKERFILE_DIR / recipe["dockerfile"])]
    args = {"IMAGE": target["image"], "IMAGE_VER": target["image_ver"]}
    if "packages" in recipe:
        args["PACKAGES"] = target.get("packages", recipe["packages"])
    else:
        args["VERSION"] = target["version"]
    if target.get("extra_pip"):
        args["EXTRA_PIP"] = target["extra_pip"]
    for key, value in args.items():
        cmd += ["--build-arg", f"{key}={value}"]
    docker(*cmd, str(HERE), timeout=1800)


def installed_version(target: dict, tag: str) -> str:
    recipe = RECIPES[target["recipe"]]
    if "version" not in recipe:
        return target["version"]
    out = docker("run", "--rm", "--entrypoint", "sh", tag, "-c", recipe["version"]).stdout.strip()
    if not out:
        raise RuntimeError("could not determine the installed package version")
    return out


def fingerprint_server(target: dict, tag: str) -> dict:
    name = "hg-" + slug(target)
    docker("rm", "-f", name, check=False)
    docker(
        "run", "-d", "--name", name, "--network", NETWORK, "--entrypoint", "sh", tag,
        "-c", RECIPES[target["recipe"]]["server"],
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 30
        while True:
            proc = docker(
                "run", "--rm", "--network", NETWORK, COLLECTOR_IMAGE,
                "--probe", f"{name}:22", "-l", "json", "-o", "-", "--timeout", "5",
                check=False,
            )  # fmt: skip
            if proc.stdout.startswith("{"):
                return json.loads(proc.stdout.splitlines()[0])
            if time.monotonic() > deadline:
                logs = docker("logs", "--tail", "8", name, check=False)
                raise RuntimeError(f"server never answered: {proc.stderr.strip()}\n{logs.stderr}{logs.stdout}")
            time.sleep(1)
    finally:
        docker("rm", "-f", name, check=False)


def fingerprint_client(target: dict, tag: str) -> dict:
    global _next_port
    with _lock:
        port, _next_port = _next_port, _next_port + 1
    if port > LAST_PORT:
        raise RuntimeError("collector port range exhausted")
    proc = docker(
        "run", "--rm", "--network", NETWORK, "-e", f"HOST={COLLECTOR}", "-e", f"PORT={port}",
        "--entrypoint", "sh", tag, "-c", RECIPES[target["recipe"]]["client"],
        check=False, timeout=90,
    )  # fmt: skip
    for _ in range(10):
        record = collector_client_record(port)
        if record:
            return record
        time.sleep(0.5)
    raise RuntimeError(f"client never connected: {(proc.stderr or proc.stdout).strip()[-400:]}")


def run_target(target: dict, roles: list[str], force: bool) -> dict[str, dict]:
    """Build one target and fingerprint the requested roles. Results are cached."""
    tag = "hasshgen/" + slug(target)
    results, todo = {}, []
    for role in roles:
        cache = WORK_DIR / role / (slug(target) + ".json")
        if cache.exists() and not force:
            results[role] = json.loads(cache.read_text())
        else:
            todo.append(role)
    if not todo:
        return results
    build(target, tag)
    version = installed_version(target, tag)
    client_name, server_name = RECIPES[target["recipe"]]["names"]
    for role in todo:
        if role == "server":
            r = fingerprint_server(target, tag)
            row = {
                "image": target["image"], "imageVersion": target["image_ver"],
                "sshServer": server_name, "sshServerVersion": version,
                "serverIdentificationString": r["server"],
                "hasshServer": r["hasshServer"], "hasshServerAlgorithms": r["hasshServerAlgorithms"],
            }  # fmt: skip
            keep = ("hasshVersion", "skex", "seastc", "smastc", "scastc", "slcts", "slstc",
                    "seacts", "smacts", "scacts", "sshka")  # fmt: skip
        else:
            r = fingerprint_client(target, tag)
            row = {
                "image": target["image"], "imageVersion": target["image_ver"],
                "sshClient": client_name, "sshClientVersion": version,
                "clientIdentificationString": r["client"],
                "hassh": r["hassh"], "hasshAlgorithms": r["hasshAlgorithms"],
            }  # fmt: skip
            keep = ("hasshVersion", "ckex", "ceacts", "cmacts", "ccacts", "clcts", "clstc",
                    "ceastc", "cmastc", "ccastc", "cshka")  # fmt: skip
        row.update((k, r[k]) for k in keep)
        cache = WORK_DIR / role / (slug(target) + ".json")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(row))
        results[role] = row
    return results


# --------------------------------------------------------------------------
# database files
# --------------------------------------------------------------------------
def update_db(base: Path, rows: list[dict], role: str) -> tuple[int, int]:
    """Merge rows into <base>.json (JSON lines) and <base>.csv.

    Returns (rows added, total rows). Existing rows keep their position.
    """
    soft = "sshClient" if role == "client" else "sshServer"
    ident = "clientIdentificationString" if role == "client" else "serverIdentificationString"
    fp = "hassh" if role == "client" else "hasshServer"

    def key(row: dict) -> tuple:
        return (row["image"], row["imageVersion"], row[soft], row[soft + "Version"])

    json_path, csv_path = base.with_suffix(".json"), base.with_suffix(".csv")
    merged: dict[tuple, dict] = {}
    if json_path.exists():
        for line in json_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                merged[key(row)] = row
    before = len(merged)
    for row in rows:
        merged[key(row)] = row
    with json_path.open("w", encoding="utf-8") as fh:
        for row in merged.values():
            fh.write(json.dumps(row) + "\n")
    columns = ["image", "imageVersion", soft, soft + "Version", ident, fp, "hasshVersion", fp + "Algorithms"]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(columns)
        # Newest first, as in the original database.
        for row in reversed(list(merged.values())):
            writer.writerow([row[c] for c in columns])
    return len(merged) - before, len(merged)


# --------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--targets", default=str(HERE / "targets.json"), help="JSON list of targets")
    parser.add_argument("-m", "--mode", choices=["server", "client", "all"], default="all")
    parser.add_argument("-j", "--jobs", type=int, default=4, help="targets processed in parallel")
    parser.add_argument("-k", "--filter", help="only targets whose name matches this regular expression")
    parser.add_argument("--force", action="store_true", help="ignore cached results in .hasshgen/")
    parser.add_argument("--no-update", action="store_true", help="do not rewrite the fingerprint databases")
    parser.add_argument("--keep-images", action="store_true", help="keep the per-target images after the run")
    parser.add_argument("--list", action="store_true", help="list target names and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    targets = json.loads(Path(args.targets).read_text())
    if args.filter:
        targets = [t for t in targets if re.search(args.filter, slug(t))]
    if args.list:
        print("\n".join(slug(t) for t in targets))
        return 0
    roles = ["server", "client"] if args.mode == "all" else [args.mode]

    # Base images that were not on this machine before the run are removed
    # again once the last target using them is done, to bound disk usage.
    users: dict[str, int] = {}
    pulled: set[str] = set()
    for target in targets:
        base = f"{target['image']}:{target['image_ver']}"
        users[base] = users.get(base, 0) + 1
        if base not in pulled and docker("image", "inspect", base, check=False).returncode != 0:
            pulled.add(base)

    def work(target: dict) -> dict[str, dict]:
        base = f"{target['image']}:{target['image_ver']}"
        try:
            return run_target(target, roles, args.force)
        finally:
            if not args.keep_images:
                with _lock:
                    users[base] -= 1
                    docker("rmi", "-f", "hasshgen/" + slug(target), check=False)
                    if users[base] == 0 and base in pulled:
                        docker("rmi", base, check=False)
                    docker("builder", "prune", "-f", check=False)

    start_collector()
    rows: dict[str, list[dict]] = {role: [] for role in roles}
    failed = []
    try:
        with ThreadPoolExecutor(args.jobs) as pool:
            futures = {pool.submit(work, t): t for t in targets}
            for done, future in enumerate(as_completed(futures), 1):
                name = slug(futures[future])
                try:
                    result = future.result()
                except Exception as exc:  # keep going: one broken image must not stop the run
                    failed.append(name)
                    print(f"[-] ({done}/{len(targets)}) {name}: {exc}", flush=True)
                    continue
                summary = []
                for role, row in result.items():
                    summary.append(row["hassh" if role == "client" else "hasshServer"])
                print(f"[+] ({done}/{len(targets)}) {name}: {' '.join(summary)}", flush=True)
        # Database order follows the target list, not completion order.
        for target in targets:
            for role in roles:
                cache = WORK_DIR / role / (slug(target) + ".json")
                if cache.exists():
                    rows[role].append(json.loads(cache.read_text()))
    finally:
        stop_collector()

    if not args.no_update:
        for role in roles:
            added, total = update_db(CLIENT_DB if role == "client" else SERVER_DB, rows[role], role)
            print(f"[=] {role} database: {added} new, {total} total")
    if failed:
        print(f"[-] {len(failed)} target(s) failed: {', '.join(failed)}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
