# hassh (Python)

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Extracts [HASSH](../README.md) fingerprints of SSH clients and servers from
capture files and live traffic, or actively: by probing a server or by
listening for clients.

Version 2 is a rewrite with **no dependencies** (the 1.x script needed
tshark and pyshark). It needs Python 3.9 or newer.

## Getting started

Run it straight from a checkout:

    python3 hassh.py -h

or install the `hassh` command:

    pip install ./python

```
usage: hassh [-h] [-V] [-r READ_FILE] [-d READ_DIRECTORY] [-i INTERFACE]
             [--probe HOST[:PORT] [HOST[:PORT] ...]]
             [--listen [ADDR:]PORT[-PORT]] [-fp {client,server,all}]
             [-f BPF_FILTER] [-l {json,csv}] [-o OUTPUT_FILE] [-w WRITE_PCAP]
             [-p] [--count COUNT] [--timeout TIMEOUT] [--no-lookup]

Extract HASSH fingerprints of SSH clients and servers.

input (choose one):
  -r, --read_file READ_FILE
                        pcap or pcapng file to process ('-' for stdin)
  -d, --read_directory READ_DIRECTORY
                        directory of capture files to process
  -i, --interface INTERFACE
                        listen on interface (uses tcpdump)
  --probe HOST[:PORT] [HOST[:PORT] ...]
                        connect to SSH servers and print their hasshServer
  --listen [ADDR:]PORT[-PORT]
                        accept SSH clients on a port or port range and print
                        their hassh

options:
  -fp, --fingerprint {client,server,all}
                        client or server fingerprint. Default: all
  -f, --bpf_filter BPF_FILTER
                        BPF capture filter (live capture only). Default: 'tcp
                        port 22 or tcp port 2222'
  -l, --log_format {json,csv}
                        output log format
  -o, --output_file OUTPUT_FILE
                        output log file, '-' for stdout. Default: hassh.log
  -w, --write_pcap WRITE_PCAP
                        save the live captured packets to this file
  -p, --print_output    print the output
  --count COUNT         with --listen: exit after this many clients
  --timeout TIMEOUT     socket timeout for --probe/--listen
  --no-lookup           do not match against the fingerprint database
```

## Usage

* Fingerprint a server without capturing anything. Only the identification
  string is sent; no key exchange or authentication takes place:

```
$ python3 hassh.py --probe test.example.org

[+] Server SSH_MSG_KEXINIT detected
    [ 192.0.2.10:22 -> 10.1.2.3:53112 ]
        [-] Identification String: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
        [-] hasshServer: e42184b06d45385a906f0803d04c83da
        [-] hasshServer Algorithms: sntrup761x25519-sha512@openssh.com,curve25519-sha256,...
        [-] Known as: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, SSH-2.0-OpenSSH_9.6
```

* Fingerprint whatever SSH client connects to you:

```
$ python3 hassh.py --listen 2222 &
$ ssh -p 2222 localhost
```

* Live network traffic capture (needs `tcpdump` and capture privileges):

```
$ sudo python3 hassh.py -i eth0 -l json -o hassh.json --print_output
```

* Read capture files (pcap or pcapng). SSH is recognised on **any** port from
  its identification string, and the client is whoever sent the SYN:

```
$ python3 hassh.py -r traffic.pcap -l csv -o hassh.csv --print_output
$ tcpdump -r traffic.pcap -w - 'tcp' | python3 hassh.py -r - -l json -o -
```

JSON output (one object per line; the field names are unchanged from 1.x):

```
{"timestamp": "2018-09-04T18:57:03.644663", "sourceIp": "10.1.2.3", "destinationIp": "192.1.2.3", "sourcePort": "52068", "destinationPort": "22", "client": "SSH-2.0-OpenSSH_7.6", "hassh": "06046964c022c6407d15a27b12a6a4fb", "hasshAlgorithms": "curve25519-sha256,...;chacha20-poly1305@openssh.com,...;umac-64-etm@openssh.com,...;none,zlib@openssh.com,zlib", "hasshVersion": "1.0", "ckex": "...", "ceacts": "...", "cmacts": "...", "ccacts": "...", "clcts": "", "clstc": "", "ceastc": "...", "cmastc": "...", "ccastc": "...", "cshka": "..."}
{"timestamp": "2018-09-04T18:57:03.673866", "sourceIp": "192.1.2.3", "destinationIp": "10.1.2.3", "sourcePort": "22", "destinationPort": "52068", "server": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4", "hasshServer": "d43d91bc39d5aaed819ad9f6b57b7348", "hasshServerAlgorithms": "...", "hasshVersion": "1.0", "skex": "...", "seastc": "...", "smastc": "...", "scastc": "...", "slcts": "", "slstc": "", "seacts": "...", "smacts": "...", "scacts": "...", "sshka": "..."}
```

CSV output:

```
timestamp,sourceIp,destinationIp,sourcePort,destinationPort,hasshType,identificationString,hassh,hasshVersion,hasshAlgorithms,kexAlgs,encAlgs,macAlgs,cmpAlgs
```

## As a library

```python
from hassh import parse_kexinit
from hassh.net import probe
from hassh.pcap import iter_kexinit

event = probe("test.example.org", 22)
print(event.banner, event.kexinit.hassh_server)

with open("traffic.pcap", "rb") as fh:
    for event in iter_kexinit(fh):
        k = event.kexinit
        print(event.src, "client" if event.is_client else "server", k.hassh if event.is_client else k.hassh_server)
```

## Changes from 1.x

* No tshark / pyshark; pure standard library.
* `--probe` and `--listen` active modes.
* SSH detected on any port; `-da/--decode_as` is accepted and ignored.
* Client/server decided by the TCP handshake rather than by comparing port
  numbers (the port heuristic remains the fallback when the capture misses
  the handshake).
* The identification string is now reliably attached to its KEXINIT (1.x
  keyed it on the source port twice and usually logged `null`).
* A log file is only written with `-l`; without `-l` results are printed.
* Results are matched against the [fingerprint database](hasshGen/). A name in
  brackets after a match is a hardening profile applied in the lab;
  `(observed)` marks a server fingerprint only known from internet scans.

## Docker

```
$ cd python
$ docker build -t hassh:latest -f docker/Dockerfile .
$ docker run --rm hassh:latest --probe test.example.org
$ docker run --rm -v ~/pcap:/data hassh:latest -d /data -l json -o /data/hassh.json
$ docker run --rm --net=host --cap-add=NET_RAW hassh:latest -i any -p
```

Host networking only works on Linux hosts.

## Tests

```
$ pip install -e '.[dev]'
$ pytest
```
