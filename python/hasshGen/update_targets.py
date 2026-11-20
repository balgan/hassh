#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
"""Find releases of the software in targets.json that are not in it yet.

Looks at the places the projects publish their releases:

  OpenSSH portable   cdn.openbsd.org release directory
  Dropbear           matt.ucc.asn.au release directory
  Paramiko           PyPI
  x/crypto/ssh (Go)  proxy.golang.org
  OpenWrt            downloads.openwrt.org
  distributions      image tags on Docker Hub and quay.io

Without options the new targets are only listed. With --run they are built
and fingerprinted with hasshgen.py, and the ones that worked are added to
targets.json and to the databases; the others are reported and found again
next time. A weekly workflow (.github/workflows/update-fingerprints.yml)
does this and opens a pull request.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGETS = HERE / "targets.json"
USER_AGENT = "hasshgen-update/1.0"

# recipe -> (page listing the releases, pattern whose first group is the version)
UPSTREAM = {
    "openssh-src": (
        "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/",
        r"openssh-(\d+\.\d+(?:\.\d+)?p\d+)\.tar\.gz",
    ),
    "dropbear-src": ("https://matt.ucc.asn.au/dropbear/releases/", r"dropbear-(\d{4}\.\d+)\.tar\.bz2"),
    "paramiko": ("https://pypi.org/simple/paramiko/", r"paramiko-(\d+(?:\.\d+)+)\.tar\.gz"),
    "go-ssh": ("https://proxy.golang.org/golang.org/x/crypto/@v/list", r"^(v\d+\.\d+\.\d+)$"),
}
OPENWRT = ("https://downloads.openwrt.org/releases/", r'href="(\d\d\.\d\d\.\d+)/"')

# image -> pattern of the tags that are releases (rolling tags are never new)
IMAGE_TAGS = {
    "alpine": r"3\.\d+",
    "ubuntu": r"\d\d\.(?:04|10)",
    "debian": r"[a-z]+-slim",
    "fedora": r"\d+",
    "rockylinux/rockylinux": r"\d+",
    "almalinux": r"\d+",
    "oraclelinux": r"\d+",
    "amazonlinux": r"\d{4}",
    "opensuse/leap": r"(?:1[5-9]|[2-3]\d)\.\d+",  # not the old 42.x numbering
    "quay.io/centos/centos": r"stream\d+",
}
# Debian tags that are not release code names
NOT_A_RELEASE = {"stable", "oldstable", "oldoldstable", "testing", "unstable", "experimental", "latest"}


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https URLs
        return response.read().decode("utf-8", "replace")


def version_key(version: str) -> tuple[int, ...]:
    """'10.6p2' -> (10, 6, 2); 'v0.41.0' -> (0, 41, 0); 'stream10' -> (10,)"""
    return tuple(int(n) for n in re.findall(r"\d+", version))


def image_tags(image: str) -> list[str]:
    """All tags of an image on Docker Hub or quay.io."""
    if image.startswith("quay.io/"):
        repository = image.split("/", 1)[1]
        tags, page = [], 1
        while page <= 20:
            data = json.loads(
                fetch(f"https://quay.io/api/v1/repository/{repository}/tag/?onlyActiveTags=true&limit=100&page={page}")
            )
            tags += [tag["name"] for tag in data.get("tags", [])]
            if not data.get("has_additional"):
                break
            page += 1
        return tags
    repository = image if "/" in image else f"library/{image}"
    url = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size=100"
    if image == "debian":  # thousands of dated tags; the releases we use end in -slim
        url += "&name=-slim"
    # Most recently pushed first, which is where a new release shows up.
    # Docker Hub refuses to page further than this.
    tags = []
    for _ in range(10):
        data = json.loads(fetch(url))
        tags += [tag["name"] for tag in data.get("results", [])]
        url = data.get("next")
        if not url:
            break
    return tags


def new_upstream(targets: list[dict], recipe: str, listing: str) -> list[dict]:
    """Releases newer than the newest one we have of a source-built recipe."""
    have = [t for t in targets if t["recipe"] == recipe]
    if not have:
        return []
    pattern = UPSTREAM[recipe][1]
    versions = set(re.findall(pattern, listing, re.M))
    newest = max(have, key=lambda t: version_key(t["version"]))
    template = {k: v for k, v in newest.items() if k != "profiles"}
    known = {t["version"] for t in have}
    return [
        {**template, "version": version}
        for version in sorted(versions - known, key=version_key)
        if version_key(version) > version_key(newest["version"])
    ]


def new_openwrt(targets: list[dict], listing: str) -> list[dict]:
    """The latest point release of every OpenWrt series, when we lack it."""
    have = [t for t in targets if t["recipe"] == "openwrt-dropbear"]
    if not have:
        return []
    latest: dict[tuple[int, ...], str] = {}
    for version in re.findall(OPENWRT[1], listing):
        series = version_key(version)[:2]
        if series not in latest or version_key(version) > version_key(latest[series]):
            latest[series] = version
    newest = max(have, key=lambda t: version_key(t["image_ver"]))
    known = {t["image_ver"] for t in have}
    oldest = min(version_key(t["image_ver"])[:2] for t in have)
    return [
        {**newest, "image_ver": version}
        for series, version in sorted(latest.items())
        if version not in known and series >= oldest
    ]


def new_images(targets: list[dict], image: str, tags: list[str]) -> list[dict]:
    """Distribution releases newer than the newest one we have of an image."""
    pattern = re.compile(IMAGE_TAGS[image])
    have = [t for t in targets if t["image"] == image and pattern.fullmatch(t["image_ver"])]
    if not have:
        return []
    releases = {tag for tag in tags if pattern.fullmatch(tag)}
    if image == "debian":
        # Code names carry no order: anything we have not seen is new. Old
        # releases keep their tag on Docker Hub but are built from debian/eol.
        known = {t["image_ver"] for t in targets if t["image"] in ("debian", "debian/eol")}
        fresh = sorted(tag for tag in releases - known if tag.split("-")[0] not in NOT_A_RELEASE)
        newest_ver = have[-1]["image_ver"]
    else:
        newest_ver = max((t["image_ver"] for t in have), key=version_key)
        fresh = sorted(
            (tag for tag in releases if version_key(tag) > version_key(newest_ver)),
            key=version_key,
        )
    templates = [t for t in have if t["image_ver"] == newest_ver]
    return [
        {**{k: v for k, v in template.items() if k != "profiles"}, "image_ver": tag}
        for tag in fresh
        for template in templates
    ]


def discover(targets: list[dict]) -> tuple[list[dict], list[str]]:
    """New targets, and the sources that could not be read."""
    found: list[dict] = []
    errors: list[str] = []

    def attempt(name: str, function) -> None:
        try:
            found.extend(function())
        except (OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(f"{name}: {exc}")

    for recipe, (url, _) in UPSTREAM.items():
        attempt(recipe, lambda recipe=recipe, url=url: new_upstream(targets, recipe, fetch(url)))
    attempt("openwrt", lambda: new_openwrt(targets, fetch(OPENWRT[0])))
    for image in IMAGE_TAGS:
        attempt(image, lambda image=image: new_images(targets, image, image_tags(image)))
    return found, errors


def insert(targets: list[dict], new: dict) -> None:
    """Put a target after the last one of the same recipe and image."""
    position = len(targets)
    for index, target in enumerate(targets):
        if target["recipe"] == new["recipe"] and target["image"] == new["image"]:
            position = index + 1
    if position == len(targets):
        for index, target in enumerate(targets):
            if target["recipe"] == new["recipe"]:
                position = index + 1
    targets.insert(position, new)


def write_targets(path: Path, targets: list[dict]) -> None:
    path.write_text("[\n" + ",\n".join(json.dumps(t) for t in targets) + "\n]\n")


def name(target: dict) -> str:
    return " ".join(str(target[k]) for k in ("recipe", "image", "image_ver", "version") if k in target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--targets", default=str(TARGETS))
    parser.add_argument("--run", action="store_true", help="fingerprint the new targets and add the ones that work")
    parser.add_argument("-j", "--jobs", type=int, default=4)
    parser.add_argument("--summary", help="write a markdown summary to this file")
    args = parser.parse_args()

    path = Path(args.targets)
    targets = json.loads(path.read_text())
    found, errors = discover(targets)
    lines = [f"new: {name(t)}" for t in found] + [f"could not check {e}" for e in errors]
    print("\n".join(lines) if lines else "nothing new")

    added, failed = [], []
    if args.run and found:
        import hasshgen  # noqa: PLC0415 - needs Docker, only for --run

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(found, fh)
        subprocess.run(  # noqa: S603
            [sys.executable, str(HERE / "hasshgen.py"), "-t", fh.name, "-j", str(args.jobs)], check=False
        )
        Path(fh.name).unlink()
        for target in found:
            cached = [
                (hasshgen.WORK_DIR / role / hasshgen.cache_name(target)).exists() for role in ("server", "client")
            ]
            if any(cached):
                insert(targets, target)
                added.append(target)
            else:
                failed.append(target)
        if added:
            write_targets(path, targets)
    if args.summary:
        text = []
        if added:
            text += ["New releases fingerprinted:", ""] + [f"- {name(t)}" for t in added] + [""]
        if failed:
            text += (
                ["Found but could not be built (will be tried again):", ""] + [f"- {name(t)}" for t in failed] + [""]
            )
        if errors:
            text += ["Sources that could not be checked:", ""] + [f"- {e}" for e in errors] + [""]
        Path(args.summary).write_text("\n".join(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
