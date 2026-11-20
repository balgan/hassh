# hasshGen

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Builds many versions of SSH software in containers and records their HASSH
fingerprints. The results are the databases in this directory:

| file | content |
|---|---|
| [hassh_fingerprints.json](hassh_fingerprints.json) / [.csv](hassh_fingerprints.csv) | client fingerprints (`hassh`) |
| [hasshserver_fingerprints.json](hasshserver_fingerprints.json) / [.csv](hasshserver_fingerprints.csv) | server fingerprints (`hasshServer`) built in the lab |
| [hasshserver_observed.json](hasshserver_observed.json) / [.csv](hasshserver_observed.csv) | server fingerprints only known from internet scans, see [below](#observed-fingerprints) |

The JSON files hold one object per line with every KEXINIT name-list; the CSV
files are the short form.

## What is covered

Listed in [targets.json](targets.json):

* **OpenSSH portable** built from every upstream release tarball, 5.3p1 to 10.6p2
* **Dropbear** built from upstream release tarballs, 2012.55 to 2026.94
* **Paramiko** 2.4.2 to 5.1.0 from PyPI, as client and as server
* **golang.org/x/crypto/ssh** with library defaults, 2019 to today: what the
  many Go-based servers (Gitea, SFTPGo, honeypots, ...) present unless they
  configure their own lists
* **Distribution packages** of OpenSSH and Dropbear on Alpine, Debian, Ubuntu,
  Fedora, CentOS, Rocky, Alma, Oracle and Amazon Linux, Red Hat UBI and
  openSUSE, including releases long past end of life (CentOS 6, Debian 6
  to 9, Ubuntu 12.04 to 16.04) because plenty of them are still online.
  Distributions change the algorithm lists (Red Hat's crypto policies most
  of all), so their fingerprints differ from upstream's for the same
  version number.
* **OpenWrt** 14.07 to 25.12: Dropbear as built for the firmware images,
  taken from the published root filesystems.
* **Configuration profiles** ([profiles.json](profiles.json)), applied to
  distribution packages and to upstream builds. These rows carry the profile
  name in `configuration`:
  * the widely copied `KexAlgorithms` / `Ciphers` / `MACs` recommendations:
    Mozilla, ssh-audit (current and 2023), "Secure Secure Shell", CIS,
    dev-sec hardening (Ansible, Chef, Puppet), ansible-lockdown;
  * the Terrapin (CVE-2023-48795) workarounds that remove ChaCha20-Poly1305
    and/or the encrypt-then-MAC modes, and `Compression no`;
  * the system-wide crypto policies of Fedora and RHEL 8+ (`LEGACY`,
    `FUTURE`, `FIPS`, `DEFAULT:SHA1`, `DEFAULT:NO-SHA1`);
  * vendor configurations of upstream OpenSSH: Google Container-Optimized OS.

Client rows from the original 2018 database (Paramiko 1.13 to 2.4.1,
Dropbear 2012.55 to 2018.76, ...) are kept as they were.

Source builds use default `configure` options. A fingerprint identifies a
build *and* its configuration: apart from the profiles every
server runs as installed, and a host with its own `KexAlgorithms` /
`Ciphers` / `MACs` only matches if somebody else made the same edit and it
ended up in the observed database.

## How it works

```
                     docker network "hasshgen"
  +--------------------+   probe :22    +---------------------------+
  |     collector      | -------------> | server under test (sshd)  |  -> hasshServer
  | (python -m hassh)  |                +---------------------------+
  | listens on         |   connect      +---------------------------+
  | 10000-11999        | <------------- | client under test (ssh)   |  -> hassh
  +--------------------+  own port each +---------------------------+
```

A single collector container runs the [hassh](../README.md) tool. Each
implementation is built into its own image. Servers are started and probed
by the collector; clients connect to the collector, each to its own port, so
any number can run at the same time and still be told apart. Nothing
listens on the host and no packet capture is involved. Nobody ever
authenticates: the collector hangs up as soon as it has the KEXINIT.

## Usage

Needs Docker and Python 3.9+; nothing else.

```
$ python3 hasshgen.py                       # everything, clients and servers
$ python3 hasshgen.py -m server -j 8        # only hasshServer, 8 targets at a time
$ python3 hasshgen.py -k 'openssh-src.*10\.' # only targets matching a regex
$ python3 hasshgen.py --list
```

```
[+] (1/3) openssh-src-debian-bookworm-slim-10.6p2: 671c5858369db8e0a60108d866bbf8ec eeca2460550b9ded084ecf2f70a75356
[+] (2/3) dropbear-src-debian-bookworm-slim-2026.94: 223440d715dad2172ff5f50e87dc537a 86deebba947efa46686aa1f4c26b334c
[+] (3/3) rpm-openssh-rockylinux-8: 686e20b21417c07a18d6311d1e29dacb a2a7e3805543a29c522f9a3fa5998efd
[=] server database: 3 new, 3 total
[=] client database: 3 new, 52 total
```

Results are cached in `.hasshgen/`, so an interrupted run resumes where it
stopped (`--force` re-runs). Images are deleted as soon as a target is done,
base images that were pulled for the run included, and the build cache is
pruned along the way; `--keep-images` turns that off.

Images that only exist for another CPU architecture (`"platform"` in the
target, e.g. CentOS 6 or the OpenSSH 5.x and 6.x source builds, whose
`configure` predates arm64) run emulated.

### Adding a version

Append a line to [targets.json](targets.json):

```json
{"recipe": "openssh-src", "image": "debian", "image_ver": "bookworm-slim", "version": "10.7p1"}
{"recipe": "apt-openssh", "image": "ubuntu", "image_ver": "27.04"}
```

Package recipes install whatever version the release currently ships and
record it. For another SSH implementation add a recipe to `RECIPES` in
`hasshgen.py`: a Dockerfile plus the shell commands that start its server and
its client.

### Configuration profiles

A target can list `"profiles"`: after the default run the same image is
started once per profile with its `options` on the sshd command line
(lists may be relative, as in `Ciphers -chacha20-poly1305@openssh.com`), or
after `update-crypto-policies --set` for a profile with a `crypto_policy`.
A server that does not know one of the algorithms or the policy refuses to
start, exactly as it would for an administrator, and that combination is
skipped. Add a profile to [profiles.json](profiles.json) with the URL it
was taken from.

## Keeping up to date

`update_targets.py` looks where the projects publish their releases (the
OpenSSH and Dropbear release directories, PyPI, the Go module proxy,
downloads.openwrt.org, and image tags on Docker Hub and quay.io) for
anything newer than what [targets.json](targets.json) has:

```
$ python3 update_targets.py          # list what is new
$ python3 update_targets.py --run    # build it, fingerprint it, add what worked
```

The [weekly workflow](../../.github/workflows/update-fingerprints.yml) runs
this, also rebuilds the distribution packages (`--force --changed-only`: a
package update only adds a row when the fingerprint changed), removes
observed fingerprints the lab has caught up with (`harvest.py --prune`),
and opens a pull request with the result. It needs the repository setting
*Allow GitHub Actions to create and approve pull requests*.

## Observed fingerprints

No lab reaches everything that answers on port 22: routers and switches,
vendor firmware, Windows and BSD builds, and every hand-edited
`sshd_config`. `harvest.py` fills that gap from scan data. It takes
observations grouped by identification string and fingerprint and writes
every fingerprint the lab database does not have to
`hasshserver_observed.json`, labelled with the identification strings of
the hosts presenting it:

```
$ python3 harvest.py observations.json
```

`observations.json` is a JSON array of
`{"day": ..., "banner": ..., "hassh_server": ..., "algos": ..., "ips": ..., "nets": ...}`.
A fingerprint is taken when at least 20 hosts present it in every scan of
the file; an identification string is only attached to it when it was seen
on at least 10 distinct networks, so a banner one organisation made up for
itself is never published. No host counts are written, only a `prevalence`
class (`common`: at least 0.1% of scanned hosts, `uncommon`: at least 0.01%,
`rare`). These rows say what hosts *claim* to be: unlike the lab rows nobody
built the software to check.

The `hassh` tool consults both files and marks these matches `(observed)`.

## Validating against real-world data

`validate.py` compares the server database with observations of real
hosts, for instance an internet-wide scan grouped by identification string
and hasshServer:

```
$ python3 validate.py observations.json
confirmed SSH-2.0-OpenSSH_9.6p1   e42184b06d45385a906f0803d04c83da  95.6% of the hosts announcing this version, rank 1  [ubuntu:24.04]
...
```

`observations.json` is a JSON array of `{"banner": ..., "hassh_server": ..., "ips": ...}`.
See [VALIDATION.md](VALIDATION.md) for the result of the last run.
