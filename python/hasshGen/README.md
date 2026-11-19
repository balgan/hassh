# hasshGen

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Builds many versions of SSH software in containers and records their HASSH
fingerprints. The results are the databases in this directory:

| file | content |
|---|---|
| [hassh_fingerprints.json](hassh_fingerprints.json) / [.csv](hassh_fingerprints.csv) | client fingerprints (`hassh`) |
| [hasshserver_fingerprints.json](hasshserver_fingerprints.json) / [.csv](hasshserver_fingerprints.csv) | server fingerprints (`hasshServer`) |

The JSON files hold one object per line with every KEXINIT name-list; the CSV
files are the short form.

## What is covered

Listed in [targets.json](targets.json):

* **OpenSSH portable** built from every upstream release tarball, 7.9p1 to 10.6p2
* **Dropbear** built from every upstream release tarball, 2019.77 to 2026.94
* **Paramiko** 2.4.2 to 5.1.0 from PyPI, as client and as server
* **Distribution packages** of OpenSSH and Dropbear on Alpine, Debian, Ubuntu,
  Fedora, CentOS, Rocky, Alma, Oracle and Amazon Linux, Red Hat UBI and
  openSUSE. Distributions change the algorithm lists (Red Hat's crypto
  policies most of all), so their fingerprints differ from upstream's for
  the same version number.

Rows from the original 2018 database (OpenSSH 5.3 to 7.8, Paramiko 1.13 to
2.4.1, Dropbear 2012.55 to 2018.76) are kept as they were.

Source builds use default `configure` options and every server runs its
default configuration: a fingerprint identifies a build *and* its
configuration, so a host with hardened `KexAlgorithms`/`Ciphers`/`MACs`
will not match.

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

## Validating against real-world data

`validate.py` compares the server database with observations of real
hosts, for instance an internet-wide scan grouped by identification string
and hasshServer:

```
$ python3 validate.py observations.json
confirmed SSH-2.0-OpenSSH_9.6p1   e42184b06d45385a906f0803d04c83da  4891100 of 5117574 hosts (95.6%), rank 1  [ubuntu:24.04]
...
```

`observations.json` is a JSON array of `{"banner": ..., "hassh_server": ..., "ips": ...}`.
See [VALIDATION.md](VALIDATION.md) for the result of the last run.
