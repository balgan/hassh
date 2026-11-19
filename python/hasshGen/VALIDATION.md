# Validation of the server fingerprints

The `hasshServer` databases were checked against two internet-wide SSH scans
(2026-11-04 and 2026-11-17, about 20 and 18 million hosts), grouped by
identification string and hasshServer. The scanner records the
identification string without its comment, so `SSH-2.0-OpenSSH_9.6p1
Ubuntu-3ubuntu13.14` is compared as `SSH-2.0-OpenSSH_9.6p1`. No host counts
are published here, only shares.

## Coverage

Share of the hosts in the 2026-11-17 scan whose fingerprint is in the
database:

| database | hosts covered |
|---|---|
| lab ([hasshserver_fingerprints](hasshserver_fingerprints.csv)), version and fingerprint both match | 80.8% |
| lab, fingerprint matches | 86.3% |
| lab + observed ([hasshserver_observed](hasshserver_observed.csv)) | 99.2% |

The observed database is derived from the same kind of data, so the last
figure needs an independent check: harvested from the 2026-11-04 scan alone
and measured on the 2026-11-17 scan, lab + observed also covers 99.2%. The
published file only holds fingerprints present in both scans.

What the remaining 0.8% is: about 9,000 fingerprints that each appear on a
handful of hosts, or whose hosts all sit in a few networks. They are one-off
configurations, and by the rules in [harvest.py](harvest.py) not published.

What the lab cannot reach, and the observed database supplies (13% of
hosts): locally edited `sshd_config` files that follow no published guide,
vendor firmware builds of Dropbear, OpenSSH for Windows, network equipment
(MikroTik, Cisco, Huawei, Comware, LANCOM), and SFTP server products.

## Lab fingerprints, one by one

Checked with [validate.py](validate.py) against the 2026-11-17 scan.
**Result: 33 absent, 227 confirmed, 37 unseen of the 297 distinct (version, fingerprint) pairs.**

How to read the table:

* *confirmed* - hosts announcing this version present this fingerprint. The
  share tells how common it is among them. A low share is expected for
  upstream source builds of versions that are mostly deployed from
  distribution packages (for example plain `OpenSSH_8.0` is overwhelmingly
  RHEL 8 with its crypto policy, not an upstream build), and for hardening
  profiles, which only a minority applies.
* *unseen* - fewer than 50 hosts announce this version, so there is nothing
  to compare with. Mostly Paramiko servers, which are rarely exposed.
* *absent* - hosts announce this version, none presents the fingerprint.
  Most are a hardening profile on a release where nobody seems to use it.
  The others are Dropbear: 2026.90, whose hosts all share one other
  fingerprint (a vendor build with non-default options), and the old
  2012-2015 releases as packaged by Debian and OpenWrt, where the hosts
  still announcing those versions are other firmware builds.

A name in brackets in the last column is a hardening profile from
[profiles.json](profiles.json).

| status | identification | hasshServer | internet scan | lab source |
|---|---|---|---|---|
| absent | SSH-2.0-OpenSSH_10.0p2 | 9c732721ab21fdec0f5c464ec09a6326 | not seen; hosts announcing this version present 671c5858369db8e0a60108d866bbf8ec | debian:trixie-slim [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_6.7p1 | dbeeb757acba63693a905a30b3b75d33 | not seen; hosts announcing this version present 3711ee816d3ea9975d96c39c31c54299 | debian/eol:jessie-slim [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_6.7p1 | e5d60e0a34f5589d03c8f30c3d6e1842 | not seen; hosts announcing this version present 3711ee816d3ea9975d96c39c31c54299 | debian/eol:jessie-slim [mozilla-intermediate] |
| absent | SSH-2.0-OpenSSH_7.4 | 27a47f642345315220a754d758ce5530 | not seen; hosts announcing this version present 6832f1ce43d4397c2c0a3e2f8c94334e | amazonlinux:2 [cis-benchmark] |
| absent | SSH-2.0-OpenSSH_7.4 | 96c3abc6937bc1997379d680e4f86bf0 | not seen; hosts announcing this version present 6832f1ce43d4397c2c0a3e2f8c94334e | amazonlinux:2 [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_7.4 | dbeeb757acba63693a905a30b3b75d33 | not seen; hosts announcing this version present 6832f1ce43d4397c2c0a3e2f8c94334e | centos:7 [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_7.4p1 | 02be6cad5cf503412cd03d1ebee6a311 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian/eol:stretch-slim [cis-benchmark] |
| absent | SSH-2.0-OpenSSH_7.4p1 | 079ede81f0ca09254cda97951c43e95c | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian/eol:stretch-slim [ssh-audit-ubuntu-20.04] |
| absent | SSH-2.0-OpenSSH_7.4p1 | dbeeb757acba63693a905a30b3b75d33 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian/eol:stretch-slim [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_7.4p1 | e5d60e0a34f5589d03c8f30c3d6e1842 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian/eol:stretch-slim [mozilla-intermediate] |
| absent | SSH-2.0-OpenSSH_7.4p1 | f3093f2138ab3190d13ca08c8fae1e8e | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian/eol:stretch-slim [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_7.6p1 | dbeeb757acba63693a905a30b3b75d33 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | ubuntu:18.04 [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_7.6p1 | f3093f2138ab3190d13ca08c8fae1e8e | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | ubuntu:18.04 [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_7.9p1 | 27a47f642345315220a754d758ce5530 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian:buster-slim [cis-benchmark] |
| absent | SSH-2.0-OpenSSH_7.9p1 | 96c3abc6937bc1997379d680e4f86bf0 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian:buster-slim [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_7.9p1 | f22ef31e2e695bf263c336665ec7f1a7 | not seen; hosts announcing this version present b12d2871a1189eff20364cf5333619ee | debian:buster-slim [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_8.0 | 2a461d4f3bb6f5cb072390f026d09b60 | not seen; hosts announcing this version present 686e20b21417c07a18d6311d1e29dacb | rockylinux:8 [mozilla-intermediate] |
| absent | SSH-2.0-OpenSSH_8.0 | 96c3abc6937bc1997379d680e4f86bf0 | not seen; hosts announcing this version present 686e20b21417c07a18d6311d1e29dacb | rockylinux:8 [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_8.0 | f22ef31e2e695bf263c336665ec7f1a7 | not seen; hosts announcing this version present 686e20b21417c07a18d6311d1e29dacb | rockylinux:8 [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_8.2p1 | f22ef31e2e695bf263c336665ec7f1a7 | not seen; hosts announcing this version present 779664e66160bf75999f091fce5edb5a | ubuntu:20.04 [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_8.4p1 | 96c3abc6937bc1997379d680e4f86bf0 | not seen; hosts announcing this version present 779664e66160bf75999f091fce5edb5a | debian:bullseye-slim [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_8.4p1 | f22ef31e2e695bf263c336665ec7f1a7 | not seen; hosts announcing this version present 779664e66160bf75999f091fce5edb5a | debian:bullseye-slim [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_9.2p1 | f22ef31e2e695bf263c336665ec7f1a7 | not seen; hosts announcing this version present 425d29fe50d8e4f5e37efb6e24bcf660 | debian:bookworm-slim [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_9.9 | 35f9d34bc68f77392cc6d4a0486da92f | not seen; hosts announcing this version present b1bff636ebbdbaa9dd2ad97fd173c956 | amazonlinux:2023 [ssh-audit-ubuntu-24.04], rockylinux:9 [ssh-audit-ubuntu-24.04] |
| absent | SSH-2.0-OpenSSH_9.9 | 373309bb276e09911ff5c8332c855e87 | not seen; hosts announcing this version present b1bff636ebbdbaa9dd2ad97fd173c956 | amazonlinux:2023 [ssh-audit-ubuntu-16.04], rockylinux:9 [ssh-audit-ubuntu-16.04] |
| absent | SSH-2.0-OpenSSH_9.9 | 512aaf3fecf39e72cea07556037fbd12 | not seen; hosts announcing this version present b1bff636ebbdbaa9dd2ad97fd173c956 | amazonlinux:2023 [ssh-audit-debian-12], rockylinux:9 [ssh-audit-debian-12] |
| absent | SSH-2.0-OpenSSH_9.9 | 9c732721ab21fdec0f5c464ec09a6326 | not seen; hosts announcing this version present b1bff636ebbdbaa9dd2ad97fd173c956 | amazonlinux:2023 [ssh-audit-rhel-7], rockylinux:9 [ssh-audit-rhel-7] |
| absent | SSH-2.0-OpenSSH_9.9 | a641adb85599d0e8db80ffcd08c847d1 | not seen; hosts announcing this version present b1bff636ebbdbaa9dd2ad97fd173c956 | amazonlinux:2023 [cis-benchmark], rockylinux:9 [cis-benchmark] |
| absent | SSH-2.0-dropbear_0.52 | a26a627b7cb7d8b307da9e96731e1215 | not seen; hosts announcing this version present 1c5883ccfa14d47302279c3283d806cd | debian/eol:squeeze-slim |
| absent | SSH-2.0-dropbear_2012.55 | 16f898dd8ed8279e1055350b4e20666c | not seen; hosts announcing this version present b74b3746d7c1b9944b2e8db18f062e6f | debian/eol:wheezy-slim |
| absent | SSH-2.0-dropbear_2014.63 | a195fa6848ae34b6ef8022110d1d8582 | not seen; hosts announcing this version present fd37a2de3a72d145a51208b4837e03f6 | openwrt:14.07 |
| absent | SSH-2.0-dropbear_2015.67 | 8468ef78c288954565a80e2e1e36a35b | not seen; hosts announcing this version present 735570a9e0c2f9cd195e312ebb950567 | openwrt:15.05.1 |
| absent | SSH-2.0-dropbear_2026.90 | 223440d715dad2172ff5f50e87dc537a | not seen; hosts announcing this version present f5500b975e4bfb75838ea8d157550b94 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.0 | 1dfe050475fa2c6fb3ef6112937b1ba3 | 0.3% of hosts announcing this version, rank 9 of 180 | opensuse/leap:16.0 |
| confirmed | SSH-2.0-OpenSSH_10.0 | 669e8d7db548b468a1bee53ef02204cb | 0.9% of hosts announcing this version, rank 5 of 180 | fedora:43 |
| confirmed | SSH-2.0-OpenSSH_10.0 | 671c5858369db8e0a60108d866bbf8ec | 5.5% of hosts announcing this version, rank 2 of 180 | alpine:3.22, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 180afc78b6f30c6f8a148052a51a8e2f | 0.0% of hosts announcing this version, rank 50 of 793 | debian:trixie-slim [ssh-audit-ubuntu-22.04] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 35f9d34bc68f77392cc6d4a0486da92f | 0.0% of hosts announcing this version, rank 121 of 793 | debian:trixie-slim [ssh-audit-ubuntu-24.04] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 373309bb276e09911ff5c8332c855e87 | 0.0% of hosts announcing this version, rank 487 of 793 | debian:trixie-slim [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 4755c2ab094d9de319834d753965e58c | 0.6% of hosts announcing this version, rank 4 of 793 | debian:trixie-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 512aaf3fecf39e72cea07556037fbd12 | 0.0% of hosts announcing this version, rank 19 of 793 | debian:trixie-slim [ssh-audit-debian-12] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | 671c5858369db8e0a60108d866bbf8ec | 89.6% of hosts announcing this version, rank 1 of 793 | debian:trixie-slim, ubuntu:25.10 |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | a641adb85599d0e8db80ffcd08c847d1 | 0.0% of hosts announcing this version, rank 69 of 793 | debian:trixie-slim [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | b63b5e7b7a8185c4f2e138344f70e9bc | 0.0% of hosts announcing this version, rank 205 of 793 | debian:trixie-slim [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | ba4fbf3338a36db608fddca3964fb391 | 0.0% of hosts announcing this version, rank 15 of 793 | debian:trixie-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_10.0p2 | c75fc99d4a1bd6b4cee9bdede89ffb57 | 0.1% of hosts announcing this version, rank 8 of 793 | debian:trixie-slim [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_10.1 | 671c5858369db8e0a60108d866bbf8ec | 81.8% of hosts announcing this version, rank 1 of 4 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.2 | 671c5858369db8e0a60108d866bbf8ec | 36.3% of hosts announcing this version, rank 1 of 104 | alpine:3.23, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.2 | f6ac1ecedabc5a6096a573cdbfcfd8a2 | 30.3% of hosts announcing this version, rank 2 of 104 | fedora:44 |
| confirmed | SSH-2.0-OpenSSH_10.2p1 | 671c5858369db8e0a60108d866bbf8ec | 96.5% of hosts announcing this version, rank 1 of 385 | ubuntu:26.04 |
| confirmed | SSH-2.0-OpenSSH_10.3 | 671c5858369db8e0a60108d866bbf8ec | 39.1% of hosts announcing this version, rank 1 of 118 | alpine:3.24, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.4 | 671c5858369db8e0a60108d866bbf8ec | 10.4% of hosts announcing this version, rank 2 of 52 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.5 | 671c5858369db8e0a60108d866bbf8ec | 34.8% of hosts announcing this version, rank 1 of 79 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.5 | f6ac1ecedabc5a6096a573cdbfcfd8a2 | 6.0% of hosts announcing this version, rank 4 of 79 | fedora:45 |
| confirmed | SSH-2.0-OpenSSH_10.5p1 | 671c5858369db8e0a60108d866bbf8ec | 99.6% of hosts announcing this version, rank 1 of 9 | ubuntu:26.10 |
| confirmed | SSH-2.0-OpenSSH_10.6 | 671c5858369db8e0a60108d866bbf8ec | 63.2% of hosts announcing this version, rank 1 of 206 | alpine:edge, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_10.6 | cb7c06d1e9d4dd9f4f858afc4d680c92 | 3.8% of hosts announcing this version, rank 4 of 206 | opensuse/tumbleweed:latest |
| confirmed | SSH-2.0-OpenSSH_10.6 | f6ac1ecedabc5a6096a573cdbfcfd8a2 | 0.1% of hosts announcing this version, rank 14 of 206 | fedora:rawhide |
| confirmed | SSH-2.0-OpenSSH_10.6p2 | 671c5858369db8e0a60108d866bbf8ec | 91.4% of hosts announcing this version, rank 1 of 11 | debian:forky-slim, debian:sid-slim |
| confirmed | SSH-2.0-OpenSSH_5.3 | 0f5053d1cc689128b6db47f340f3285f | 68.7% of hosts announcing this version, rank 1 of 94 | centos:6 |
| confirmed | SSH-2.0-OpenSSH_5.3 | b1c6c0d56317555b85c7005a3de29325 | 5.0% of hosts announcing this version, rank 3 of 94 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.3 | e5d60e0a34f5589d03c8f30c3d6e1842 | 0.3% of hosts announcing this version, rank 6 of 94 | centos:6 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_5.4 | b1c6c0d56317555b85c7005a3de29325 | 91.9% of hosts announcing this version, rank 1 of 4 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.5 | b1c6c0d56317555b85c7005a3de29325 | 81.1% of hosts announcing this version, rank 1 of 7 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.5p1 | b1c6c0d56317555b85c7005a3de29325 | 97.4% of hosts announcing this version, rank 1 of 10 | debian/eol:squeeze-slim |
| confirmed | SSH-2.0-OpenSSH_5.6 | b1c6c0d56317555b85c7005a3de29325 | 41.3% of hosts announcing this version, rank 2 of 6 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.7 | 60205d0b53ffd441ead5c43b5a6f1bc7 | 100.0% of hosts announcing this version, rank 1 of 1 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.8 | 60205d0b53ffd441ead5c43b5a6f1bc7 | 70.6% of hosts announcing this version, rank 1 of 15 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.9 | ce3c327f37ea2ec21f317fbc3fd1ea43 | 47.7% of hosts announcing this version, rank 1 of 17 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_5.9p1 | ce3c327f37ea2ec21f317fbc3fd1ea43 | 96.1% of hosts announcing this version, rank 1 of 18 | ubuntu:12.04 |
| confirmed | SSH-2.0-OpenSSH_6.0 | ce3c327f37ea2ec21f317fbc3fd1ea43 | 58.7% of hosts announcing this version, rank 1 of 14 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.0p1 | ce3c327f37ea2ec21f317fbc3fd1ea43 | 91.1% of hosts announcing this version, rank 1 of 36 | debian/eol:wheezy-slim |
| confirmed | SSH-2.0-OpenSSH_6.1 | aa294de13ac7e9dbf51610dc55a8ff86 | 61.7% of hosts announcing this version, rank 1 of 12 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.2 | cca34b641961a75a15b91d1f1a13a3fb | 37.9% of hosts announcing this version, rank 1 of 22 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.3 | cca34b641961a75a15b91d1f1a13a3fb | 89.3% of hosts announcing this version, rank 1 of 3 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.4 | cca34b641961a75a15b91d1f1a13a3fb | 92.7% of hosts announcing this version, rank 1 of 11 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.5 | ba6d3d2aecbd0d91b01dfa7828110d70 | 21.9% of hosts announcing this version, rank 2 of 10 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.6 | ba6d3d2aecbd0d91b01dfa7828110d70 | 20.9% of hosts announcing this version, rank 1 of 23 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.6.1p1 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 55 of 80 | ubuntu:14.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_6.6.1p1 | ba6d3d2aecbd0d91b01dfa7828110d70 | 82.9% of hosts announcing this version, rank 1 of 80 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.6.1p1 | d84b3ff313589002f6059f1c0cfbde67 | 0.1% of hosts announcing this version, rank 14 of 80 | ubuntu:14.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_6.6.1p1 | dbeeb757acba63693a905a30b3b75d33 | 0.0% of hosts announcing this version, rank 39 of 80 | ubuntu:14.04 [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_6.6.1p1 | e5d60e0a34f5589d03c8f30c3d6e1842 | 0.0% of hosts announcing this version, rank 43 of 80 | ubuntu:14.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_6.7 | 3711ee816d3ea9975d96c39c31c54299 | 73.7% of hosts announcing this version, rank 1 of 13 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.7p1 | 3711ee816d3ea9975d96c39c31c54299 | 84.1% of hosts announcing this version, rank 1 of 72 | debian/eol:jessie-slim |
| confirmed | SSH-2.0-OpenSSH_6.7p1 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 29 of 72 | debian/eol:jessie-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_6.7p1 | d84b3ff313589002f6059f1c0cfbde67 | 0.1% of hosts announcing this version, rank 18 of 72 | debian/eol:jessie-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_6.8 | 3711ee816d3ea9975d96c39c31c54299 | 67.2% of hosts announcing this version, rank 1 of 9 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_6.9 | d43d91bc39d5aaed819ad9f6b57b7348 | 13.9% of hosts announcing this version, rank 2 of 12 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.0 | d43d91bc39d5aaed819ad9f6b57b7348 | 15.7% of hosts announcing this version, rank 2 of 66 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.1 | d43d91bc39d5aaed819ad9f6b57b7348 | 30.4% of hosts announcing this version, rank 1 of 80 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.2 | d43d91bc39d5aaed819ad9f6b57b7348 | 31.4% of hosts announcing this version, rank 1 of 109 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.2p2 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 29 of 132 | ubuntu:16.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.2p2 | d43d91bc39d5aaed819ad9f6b57b7348 | 93.5% of hosts announcing this version, rank 1 of 132 | ubuntu:16.04 |
| confirmed | SSH-2.0-OpenSSH_7.2p2 | d84b3ff313589002f6059f1c0cfbde67 | 0.2% of hosts announcing this version, rank 9 of 132 | ubuntu:16.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_7.2p2 | dbeeb757acba63693a905a30b3b75d33 | 0.0% of hosts announcing this version, rank 40 of 132 | ubuntu:16.04 [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_7.2p2 | e5d60e0a34f5589d03c8f30c3d6e1842 | 0.0% of hosts announcing this version, rank 106 of 132 | ubuntu:16.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_7.3 | 8cc1fefeb6ee94a1d6c81bc3ee13c62c | 55.1% of hosts announcing this version, rank 1 of 61 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.4 | 02be6cad5cf503412cd03d1ebee6a311 | 0.0% of hosts announcing this version, rank 125 of 686 | centos:7 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 079ede81f0ca09254cda97951c43e95c | 0.0% of hosts announcing this version, rank 511 of 686 | centos:7 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 1381d6ded24976054224ceedc9ae1938 | 0.0% of hosts announcing this version, rank 511 of 686 | amazonlinux:2 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 156 of 686 | amazonlinux:2 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 65 of 686 | centos:7 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 6832f1ce43d4397c2c0a3e2f8c94334e | 76.9% of hosts announcing this version, rank 1 of 686 | centos:7 |
| confirmed | SSH-2.0-OpenSSH_7.4 | 754f14656edef3974cc1940b0587d958 | 0.0% of hosts announcing this version, rank 584 of 686 | amazonlinux:2 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 8050722271f4c0874298b7d120bd8490 | 0.0% of hosts announcing this version, rank 66 of 686 | amazonlinux:2 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_7.4 | 98fecded130dda2056c8711b651ef4a5 | 4.9% of hosts announcing this version, rank 3 of 686 | amazonlinux:2, oraclelinux:7 |
| confirmed | SSH-2.0-OpenSSH_7.4 | b12d2871a1189eff20364cf5333619ee | 0.8% of hosts announcing this version, rank 6 of 686 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.4 | d84b3ff313589002f6059f1c0cfbde67 | 0.2% of hosts announcing this version, rank 10 of 686 | centos:7 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_7.4 | e5d60e0a34f5589d03c8f30c3d6e1842 | 0.0% of hosts announcing this version, rank 189 of 686 | centos:7 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_7.4 | f22ef31e2e695bf263c336665ec7f1a7 | 0.0% of hosts announcing this version, rank 511 of 686 | amazonlinux:2 [ssh-audit-rhel-7] |
| confirmed | SSH-2.0-OpenSSH_7.4 | f3093f2138ab3190d13ca08c8fae1e8e | 0.0% of hosts announcing this version, rank 102 of 686 | centos:7 [ssh-audit-rhel-7] |
| confirmed | SSH-2.0-OpenSSH_7.4p1 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 28 of 107 | debian/eol:stretch-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.4p1 | b12d2871a1189eff20364cf5333619ee | 92.7% of hosts announcing this version, rank 1 of 107 | debian/eol:stretch-slim |
| confirmed | SSH-2.0-OpenSSH_7.4p1 | d84b3ff313589002f6059f1c0cfbde67 | 0.2% of hosts announcing this version, rank 11 of 107 | debian/eol:stretch-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_7.5 | b12d2871a1189eff20364cf5333619ee | 68.7% of hosts announcing this version, rank 1 of 156 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.6 | b12d2871a1189eff20364cf5333619ee | 59.6% of hosts announcing this version, rank 1 of 82 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | 02be6cad5cf503412cd03d1ebee6a311 | 0.0% of hosts announcing this version, rank 45 of 162 | ubuntu:18.04 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | 079ede81f0ca09254cda97951c43e95c | 0.0% of hosts announcing this version, rank 34 of 162 | ubuntu:18.04 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | 3ee0814b6dd15587ada676465b720b06 | 0.0% of hosts announcing this version, rank 24 of 162 | ubuntu:18.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | b12d2871a1189eff20364cf5333619ee | 91.5% of hosts announcing this version, rank 1 of 162 | ubuntu:18.04 |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | d84b3ff313589002f6059f1c0cfbde67 | 0.1% of hosts announcing this version, rank 6 of 162 | ubuntu:18.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_7.6p1 | e5d60e0a34f5589d03c8f30c3d6e1842 | 0.0% of hosts announcing this version, rank 56 of 162 | ubuntu:18.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_7.7 | b12d2871a1189eff20364cf5333619ee | 45.8% of hosts announcing this version, rank 1 of 74 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.8 | b12d2871a1189eff20364cf5333619ee | 13.1% of hosts announcing this version, rank 4 of 110 | ubuntu:14.04 |
| confirmed | SSH-2.0-OpenSSH_7.9 | b12d2871a1189eff20364cf5333619ee | 12.6% of hosts announcing this version, rank 2 of 89 | alpine:3.9, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_7.9p1 | 077e440c58a35bb447c454d5fa8175b4 | 40.2% of hosts announcing this version, rank 2 of 147 | debian:buster-slim |
| confirmed | SSH-2.0-OpenSSH_7.9p1 | 1381d6ded24976054224ceedc9ae1938 | 0.0% of hosts announcing this version, rank 23 of 147 | debian:buster-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_7.9p1 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 105 of 147 | debian:buster-slim [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_7.9p1 | 754f14656edef3974cc1940b0587d958 | 0.2% of hosts announcing this version, rank 12 of 147 | debian:buster-slim [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_7.9p1 | 8050722271f4c0874298b7d120bd8490 | 0.2% of hosts announcing this version, rank 11 of 147 | debian:buster-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_8.0 | 1381d6ded24976054224ceedc9ae1938 | 0.0% of hosts announcing this version, rank 88 of 391 | rockylinux:8 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_8.0 | 27a47f642345315220a754d758ce5530 | 0.0% of hosts announcing this version, rank 38 of 391 | rockylinux:8 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_8.0 | 686e20b21417c07a18d6311d1e29dacb | 64.8% of hosts announcing this version, rank 1 of 391 | almalinux:8, oraclelinux:8, redhat/ubi8:latest, rockylinux:8 |
| confirmed | SSH-2.0-OpenSSH_8.0 | 754f14656edef3974cc1940b0587d958 | 0.0% of hosts announcing this version, rank 34 of 391 | rockylinux:8 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_8.0 | 8050722271f4c0874298b7d120bd8490 | 0.0% of hosts announcing this version, rank 28 of 391 | rockylinux:8 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_8.0 | b12d2871a1189eff20364cf5333619ee | 0.5% of hosts announcing this version, rank 7 of 391 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.0 | f64043bfb57b94caaffcf99ca8a5eb0f | 25.5% of hosts announcing this version, rank 2 of 391 | centos:8, fedora:30 |
| confirmed | SSH-2.0-OpenSSH_8.1 | b12d2871a1189eff20364cf5333619ee | 45.5% of hosts announcing this version, rank 1 of 101 | alpine:3.10, alpine:3.11, opensuse/leap:15.2, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.1 | f64043bfb57b94caaffcf99ca8a5eb0f | 2.3% of hosts announcing this version, rank 6 of 101 | fedora:31 |
| confirmed | SSH-2.0-OpenSSH_8.2 | 3ccd1778a76049721c71ad7d2bf62bbc | 11.3% of hosts announcing this version, rank 3 of 134 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 1381d6ded24976054224ceedc9ae1938 | 0.0% of hosts announcing this version, rank 20 of 336 | ubuntu:20.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 27a47f642345315220a754d758ce5530 | 0.0% of hosts announcing this version, rank 45 of 336 | ubuntu:20.04 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 224 of 336 | ubuntu:20.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 754f14656edef3974cc1940b0587d958 | 0.0% of hosts announcing this version, rank 16 of 336 | ubuntu:20.04 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 779664e66160bf75999f091fce5edb5a | 79.0% of hosts announcing this version, rank 1 of 336 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 8050722271f4c0874298b7d120bd8490 | 2.2% of hosts announcing this version, rank 3 of 336 | ubuntu:20.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_8.2p1 | 96c3abc6937bc1997379d680e4f86bf0 | 0.0% of hosts announcing this version, rank 187 of 336 | ubuntu:20.04 [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_8.3 | 3ccd1778a76049721c71ad7d2bf62bbc | 38.3% of hosts announcing this version, rank 1 of 75 | alpine:3.12, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.3 | f64043bfb57b94caaffcf99ca8a5eb0f | 6.5% of hosts announcing this version, rank 3 of 75 | fedora:32 |
| confirmed | SSH-2.0-OpenSSH_8.4 | 077e440c58a35bb447c454d5fa8175b4 | 6.9% of hosts announcing this version, rank 3 of 100 | opensuse/leap:15.4, opensuse/leap:15.5 |
| confirmed | SSH-2.0-OpenSSH_8.4 | 2307c390c7c9aba5b4c9519e72347f34 | 1.1% of hosts announcing this version, rank 4 of 100 | fedora:33 |
| confirmed | SSH-2.0-OpenSSH_8.4 | 3ccd1778a76049721c71ad7d2bf62bbc | 72.1% of hosts announcing this version, rank 1 of 100 | alpine:3.13, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.4 | b12d2871a1189eff20364cf5333619ee | 10.8% of hosts announcing this version, rank 2 of 100 | opensuse/leap:15.3 |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 1381d6ded24976054224ceedc9ae1938 | 0.1% of hosts announcing this version, rank 12 of 248 | debian:bullseye-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 27a47f642345315220a754d758ce5530 | 0.0% of hosts announcing this version, rank 46 of 248 | debian:bullseye-slim [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 29 of 248 | debian:bullseye-slim [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 754f14656edef3974cc1940b0587d958 | 0.1% of hosts announcing this version, rank 15 of 248 | debian:bullseye-slim [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 779664e66160bf75999f091fce5edb5a | 74.2% of hosts announcing this version, rank 1 of 248 | debian:bullseye-slim |
| confirmed | SSH-2.0-OpenSSH_8.4p1 | 8050722271f4c0874298b7d120bd8490 | 1.0% of hosts announcing this version, rank 3 of 248 | debian:bullseye-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_8.5 | 3ccd1778a76049721c71ad7d2bf62bbc | 6.9% of hosts announcing this version, rank 3 of 73 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.6 | 2307c390c7c9aba5b4c9519e72347f34 | 6.7% of hosts announcing this version, rank 4 of 69 | fedora:34 |
| confirmed | SSH-2.0-OpenSSH_8.6 | 3ccd1778a76049721c71ad7d2bf62bbc | 36.5% of hosts announcing this version, rank 1 of 69 | alpine:3.14, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.7 | 2307c390c7c9aba5b4c9519e72347f34 | 6.3% of hosts announcing this version, rank 2 of 223 | fedora:35 |
| confirmed | SSH-2.0-OpenSSH_8.7 | 3ccd1778a76049721c71ad7d2bf62bbc | 0.2% of hosts announcing this version, rank 12 of 223 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.8 | 2307c390c7c9aba5b4c9519e72347f34 | 3.0% of hosts announcing this version, rank 7 of 145 | fedora:36, fedora:37 |
| confirmed | SSH-2.0-OpenSSH_8.8 | 3ccd1778a76049721c71ad7d2bf62bbc | 23.8% of hosts announcing this version, rank 1 of 145 | alpine:3.15, ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.9 | 699519fdcc30cbcd093d5cd01e4b1d56 | 32.1% of hosts announcing this version, rank 1 of 97 | ubuntu:20.04 |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 1381d6ded24976054224ceedc9ae1938 | 0.1% of hosts announcing this version, rank 14 of 706 | ubuntu:22.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 27a47f642345315220a754d758ce5530 | 0.0% of hosts announcing this version, rank 31 of 706 | ubuntu:22.04 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 311 of 706 | ubuntu:22.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 41ff3ecd1458b0bf86e1b4891636213e | 90.7% of hosts announcing this version, rank 1 of 706 | ubuntu:22.04 |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 754f14656edef3974cc1940b0587d958 | 0.0% of hosts announcing this version, rank 37 of 706 | ubuntu:22.04 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 7c35edbd6b71774ac60933af0fa425ab | 0.0% of hosts announcing this version, rank 415 of 706 | ubuntu:22.04 [ssh-audit-ubuntu-24.04] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 8050722271f4c0874298b7d120bd8490 | 3.6% of hosts announcing this version, rank 2 of 706 | ubuntu:22.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | 96c3abc6937bc1997379d680e4f86bf0 | 0.0% of hosts announcing this version, rank 369 of 706 | ubuntu:22.04 [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | c43e7a91ea1d40944c30ac10c59d099d | 0.0% of hosts announcing this version, rank 57 of 706 | ubuntu:22.04 [ssh-audit-ubuntu-22.04] |
| confirmed | SSH-2.0-OpenSSH_8.9p1 | f22ef31e2e695bf263c336665ec7f1a7 | 0.0% of hosts announcing this version, rank 565 of 706 | ubuntu:22.04 [ssh-audit-rhel-7] |
| confirmed | SSH-2.0-OpenSSH_9.0 | 02d7dd8ce96185733225e6f56d67fb77 | 4.3% of hosts announcing this version, rank 6 of 46 | fedora:38 |
| confirmed | SSH-2.0-OpenSSH_9.0 | a65c3b91f743d3f246e72172e77288f1 | 2.0% of hosts announcing this version, rank 8 of 46 | alpine:3.16 |
| confirmed | SSH-2.0-OpenSSH_9.0 | a984ff804585fabe3cd08f4b3849024a | 40.2% of hosts announcing this version, rank 1 of 46 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.1 | a65c3b91f743d3f246e72172e77288f1 | 2.0% of hosts announcing this version, rank 8 of 57 | alpine:3.17 |
| confirmed | SSH-2.0-OpenSSH_9.1 | a984ff804585fabe3cd08f4b3849024a | 48.7% of hosts announcing this version, rank 1 of 57 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.2 | a984ff804585fabe3cd08f4b3849024a | 55.7% of hosts announcing this version, rank 1 of 15 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 1381d6ded24976054224ceedc9ae1938 | 0.0% of hosts announcing this version, rank 23 of 593 | debian:bookworm-slim [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 27a47f642345315220a754d758ce5530 | 0.0% of hosts announcing this version, rank 20 of 593 | debian:bookworm-slim [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 2a461d4f3bb6f5cb072390f026d09b60 | 0.0% of hosts announcing this version, rank 196 of 593 | debian:bookworm-slim [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 425d29fe50d8e4f5e37efb6e24bcf660 | 82.6% of hosts announcing this version, rank 1 of 593 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 5ace5093aaaedf7559f8a7965f4c062f | 0.0% of hosts announcing this version, rank 41 of 593 | debian:bookworm-slim [ssh-audit-debian-12] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 754f14656edef3974cc1940b0587d958 | 0.0% of hosts announcing this version, rank 35 of 593 | debian:bookworm-slim [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 7c35edbd6b71774ac60933af0fa425ab | 0.0% of hosts announcing this version, rank 163 of 593 | debian:bookworm-slim [ssh-audit-ubuntu-24.04] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 8050722271f4c0874298b7d120bd8490 | 1.7% of hosts announcing this version, rank 4 of 593 | debian:bookworm-slim [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | 96c3abc6937bc1997379d680e4f86bf0 | 0.0% of hosts announcing this version, rank 318 of 593 | debian:bookworm-slim [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_9.2p1 | c43e7a91ea1d40944c30ac10c59d099d | 0.0% of hosts announcing this version, rank 51 of 593 | debian:bookworm-slim [ssh-audit-ubuntu-22.04] |
| confirmed | SSH-2.0-OpenSSH_9.3 | 02d7dd8ce96185733225e6f56d67fb77 | 72.0% of hosts announcing this version, rank 1 of 67 | fedora:39 |
| confirmed | SSH-2.0-OpenSSH_9.3 | a65c3b91f743d3f246e72172e77288f1 | 0.8% of hosts announcing this version, rank 5 of 67 | alpine:3.18 |
| confirmed | SSH-2.0-OpenSSH_9.3 | a984ff804585fabe3cd08f4b3849024a | 2.3% of hosts announcing this version, rank 3 of 67 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.4 | a984ff804585fabe3cd08f4b3849024a | 18.8% of hosts announcing this version, rank 2 of 11 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.5 | a984ff804585fabe3cd08f4b3849024a | 43.2% of hosts announcing this version, rank 1 of 16 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.6 | 8832c6c50ec693915fff77c55b2d2f46 | 1.9% of hosts announcing this version, rank 4 of 132 | opensuse/leap:15.6 |
| confirmed | SSH-2.0-OpenSSH_9.6 | b1bff636ebbdbaa9dd2ad97fd173c956 | 66.3% of hosts announcing this version, rank 1 of 132 | fedora:40 |
| confirmed | SSH-2.0-OpenSSH_9.6 | e42184b06d45385a906f0803d04c83da | 17.1% of hosts announcing this version, rank 2 of 132 | alpine:3.19, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | 180afc78b6f30c6f8a148052a51a8e2f | 0.0% of hosts announcing this version, rank 176 of 1045 | ubuntu:24.04 [ssh-audit-ubuntu-22.04] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | 35f9d34bc68f77392cc6d4a0486da92f | 0.0% of hosts announcing this version, rank 20 of 1045 | ubuntu:24.04 [ssh-audit-ubuntu-24.04] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | 373309bb276e09911ff5c8332c855e87 | 0.0% of hosts announcing this version, rank 411 of 1045 | ubuntu:24.04 [ssh-audit-ubuntu-16.04] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | 4755c2ab094d9de319834d753965e58c | 1.0% of hosts announcing this version, rank 2 of 1045 | ubuntu:24.04 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | 9c732721ab21fdec0f5c464ec09a6326 | 0.0% of hosts announcing this version, rank 411 of 1045 | ubuntu:24.04 [ssh-audit-rhel-7] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | a641adb85599d0e8db80ffcd08c847d1 | 0.0% of hosts announcing this version, rank 9 of 1045 | ubuntu:24.04 [cis-benchmark] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | b63b5e7b7a8185c4f2e138344f70e9bc | 0.0% of hosts announcing this version, rank 340 of 1045 | ubuntu:24.04 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | ba4fbf3338a36db608fddca3964fb391 | 0.0% of hosts announcing this version, rank 67 of 1045 | ubuntu:24.04 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | c75fc99d4a1bd6b4cee9bdede89ffb57 | 0.0% of hosts announcing this version, rank 17 of 1045 | ubuntu:24.04 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_9.6p1 | e42184b06d45385a906f0803d04c83da | 96.9% of hosts announcing this version, rank 1 of 1045 | ubuntu:24.04 |
| confirmed | SSH-2.0-OpenSSH_9.7 | e42184b06d45385a906f0803d04c83da | 53.5% of hosts announcing this version, rank 1 of 59 | alpine:3.20, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.8 | e42184b06d45385a906f0803d04c83da | 18.8% of hosts announcing this version, rank 3 of 125 | debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.9 | 180afc78b6f30c6f8a148052a51a8e2f | 0.0% of hosts announcing this version, rank 73 of 573 | amazonlinux:2023 [ssh-audit-ubuntu-22.04], rockylinux:9 [ssh-audit-ubuntu-22.04] |
| confirmed | SSH-2.0-OpenSSH_9.9 | 4755c2ab094d9de319834d753965e58c | 1.9% of hosts announcing this version, rank 8 of 573 | amazonlinux:2023 [mozilla-modern], rockylinux:9 [mozilla-modern] |
| confirmed | SSH-2.0-OpenSSH_9.9 | b1bff636ebbdbaa9dd2ad97fd173c956 | 36.7% of hosts announcing this version, rank 1 of 573 | almalinux:9, amazonlinux:2023, fedora:41, fedora:42, oraclelinux:9, quay.io/centos/centos:stream9, redhat/ubi9:latest, rockylinux:9 |
| confirmed | SSH-2.0-OpenSSH_9.9 | b63b5e7b7a8185c4f2e138344f70e9bc | 0.0% of hosts announcing this version, rank 218 of 573 | amazonlinux:2023 [mozilla-intermediate], rockylinux:9 [mozilla-intermediate] |
| confirmed | SSH-2.0-OpenSSH_9.9 | ba4fbf3338a36db608fddca3964fb391 | 0.0% of hosts announcing this version, rank 155 of 573 | amazonlinux:2023 [secure-secure-shell], rockylinux:9 [secure-secure-shell] |
| confirmed | SSH-2.0-OpenSSH_9.9 | bbd3df916ddc675cc91c127ab1a90657 | 18.0% of hosts announcing this version, rank 2 of 573 | alpine:3.21, debian:bookworm-slim |
| confirmed | SSH-2.0-OpenSSH_9.9 | c75fc99d4a1bd6b4cee9bdede89ffb57 | 0.0% of hosts announcing this version, rank 158 of 573 | amazonlinux:2023 [ssh-audit-ubuntu-20.04], rockylinux:9 [ssh-audit-ubuntu-20.04] |
| confirmed | SSH-2.0-OpenSSH_9.9 | f6ac1ecedabc5a6096a573cdbfcfd8a2 | 8.0% of hosts announcing this version, rank 5 of 573 | almalinux:10, oraclelinux:10, quay.io/centos/centos:stream10, redhat/ubi10:latest, rockylinux/rockylinux:10 |
| confirmed | SSH-2.0-OpenSSH_9.9p1 | bbd3df916ddc675cc91c127ab1a90657 | 99.5% of hosts announcing this version, rank 1 of 22 | ubuntu:25.04 |
| confirmed | SSH-2.0-dropbear | 44ddf68b77ada4af80d15e4693fe4fc6 | 2.8% of hosts announcing this version, rank 8 of 97 | openwrt:24.10.8 |
| confirmed | SSH-2.0-dropbear | 514f0091e0bcc7f2db6887a1099c7536 | 3.2% of hosts announcing this version, rank 6 of 97 | openwrt:19.07.10 |
| confirmed | SSH-2.0-dropbear | 7a0c8889c1f7bfa15089b62dd642636f | 9.5% of hosts announcing this version, rank 3 of 97 | openwrt:22.03.7, openwrt:23.05.6 |
| confirmed | SSH-2.0-dropbear | 8258db1ab29ad7d30213876f2ea167ba | 6.2% of hosts announcing this version, rank 5 of 97 | openwrt:21.02.7 |
| confirmed | SSH-2.0-dropbear | b1d7a661905d38da7ec0ad1b644d4167 | 1.8% of hosts announcing this version, rank 11 of 97 | openwrt:17.01.7 |
| confirmed | SSH-2.0-dropbear | b5a30e4f205f4fa6bb7fefb42015f5e6 | 1.0% of hosts announcing this version, rank 15 of 97 | openwrt:18.06.9 |
| confirmed | SSH-2.0-dropbear | d37b92dc8fabd4d8c2cf9a8f809e5381 | 0.8% of hosts announcing this version, rank 17 of 97 | openwrt:25.12.6 |
| confirmed | SSH-2.0-dropbear_2014.65 | ad00edb0c2a031d9884826ba7b7ba41e | 18.8% of hosts announcing this version, rank 2 of 7 | debian/eol:jessie-slim |
| confirmed | SSH-2.0-dropbear_2016.72 | d93f46d063c4382b6232a4d77db532b2 | 69.6% of hosts announcing this version, rank 1 of 3 | ubuntu:16.04 |
| confirmed | SSH-2.0-dropbear_2016.74 | d93f46d063c4382b6232a4d77db532b2 | 5.7% of hosts announcing this version, rank 5 of 44 | debian/eol:stretch-slim |
| confirmed | SSH-2.0-dropbear_2017.75 | d93f46d063c4382b6232a4d77db532b2 | 13.8% of hosts announcing this version, rank 3 of 34 | ubuntu:18.04 |
| confirmed | SSH-2.0-dropbear_2018.76 | 413e646031ea5204c5ec2fe2d5b7946e | 30.2% of hosts announcing this version, rank 2 of 36 | alpine:3.9, debian:buster-slim |
| confirmed | SSH-2.0-dropbear_2019.77 | 413e646031ea5204c5ec2fe2d5b7946e | 48.9% of hosts announcing this version, rank 1 of 5 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2019.78 | 413e646031ea5204c5ec2fe2d5b7946e | 6.6% of hosts announcing this version, rank 7 of 49 | alpine:3.10, alpine:3.11, alpine:3.12, debian:bookworm-slim, ubuntu:20.04 |
| confirmed | SSH-2.0-dropbear_2020.79 | 581c7540d57c52f610b24b88b36f6084 | 27.8% of hosts announcing this version, rank 2 of 3 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2020.80 | 581c7540d57c52f610b24b88b36f6084 | 7.6% of hosts announcing this version, rank 2 of 14 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2020.81 | 581c7540d57c52f610b24b88b36f6084 | 4.5% of hosts announcing this version, rank 6 of 43 | alpine:3.13, alpine:3.14, alpine:3.15, debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2020.81 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 0.7% of hosts announcing this version, rank 20 of 43 | debian:bullseye-slim, ubuntu:22.04 |
| confirmed | SSH-2.0-dropbear_2022.82 | 581c7540d57c52f610b24b88b36f6084 | 6.3% of hosts announcing this version, rank 3 of 23 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2022.82 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 0.1% of hosts announcing this version, rank 16 of 23 | alpine:3.16 |
| confirmed | SSH-2.0-dropbear_2022.83 | 581c7540d57c52f610b24b88b36f6084 | 1.4% of hosts announcing this version, rank 9 of 30 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2022.83 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 2.5% of hosts announcing this version, rank 7 of 30 | alpine:3.17, alpine:3.18, alpine:3.19, debian:bookworm-slim, ubuntu:24.04 |
| confirmed | SSH-2.0-dropbear_2024.84 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 0.5% of hosts announcing this version, rank 8 of 11 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2024.85 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 7.4% of hosts announcing this version, rank 4 of 15 | alpine:3.20, debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2024.86 | e1a0b5f8d334ec70fe937b2d5ff8d0b6 | 20.2% of hosts announcing this version, rank 2 of 10 | alpine:3.21, debian:bookworm-slim, ubuntu:25.04 |
| confirmed | SSH-2.0-dropbear_2025.87 | 223440d715dad2172ff5f50e87dc537a | 4.5% of hosts announcing this version, rank 4 of 5 | debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2025.88 | 223440d715dad2172ff5f50e87dc537a | 42.7% of hosts announcing this version, rank 1 of 25 | alpine:3.22, alpine:3.23, debian:bookworm-slim, ubuntu:25.10 |
| confirmed | SSH-2.0-dropbear_2025.89 | 223440d715dad2172ff5f50e87dc537a | 12.0% of hosts announcing this version, rank 3 of 11 | debian:bookworm-slim, debian:trixie-slim, ubuntu:26.04 |
| confirmed | SSH-2.0-dropbear_2026.91 | 223440d715dad2172ff5f50e87dc537a | 2.4% of hosts announcing this version, rank 4 of 9 | alpine:3.24, debian:bookworm-slim |
| confirmed | SSH-2.0-dropbear_2026.94 | 223440d715dad2172ff5f50e87dc537a | 58.8% of hosts announcing this version, rank 1 of 5 | alpine:edge, debian:bookworm-slim, debian:forky-slim, debian:sid-slim, ubuntu:26.10 |
| confirmed | SSH-2.0-paramiko_2.12.0 | 335240c7e4ea08029ad79fcf794c34ef | 50.0% of hosts announcing this version, rank 1 of 2 | python:3.8-slim |
| confirmed | SSH-2.0-paramiko_2.7.2 | 3943d631b90b087bb9e8e755d6f4cfda | 100.0% of hosts announcing this version, rank 1 of 1 | python:3.8-slim |
| confirmed | SSH-2.0-paramiko_3.4.0 | 56a1be8f99f87d129d1879e4bacbbd76 | 62.5% of hosts announcing this version, rank 1 of 2 | python:3.12-slim |
| confirmed | SSH-2.0-paramiko_3.5.1 | 90edd2a13bea0aba448bca0557b6ed31 | 100.0% of hosts announcing this version, rank 1 of 1 | python:3.12-slim |
| confirmed | SSH-2.0-paramiko_4.0.0 | 90edd2a13bea0aba448bca0557b6ed31 | 100.0% of hosts announcing this version, rank 1 of 1 | python:3.12-slim |
| confirmed | SSH-2.0-paramiko_5.0.0 | 48c4b4ca3f96168c5bbbadc362b47dc5 | 100.0% of hosts announcing this version, rank 1 of 1 | python:3.12-slim |
| confirmed | SSH-2.0-paramiko_5.1.0 | 8ab61c0e42b2572fb6e55fc05f63ff41 | 100.0% of hosts announcing this version, rank 1 of 1 | python:3.12-slim |
| unseen | SSH-2.0-dropbear_2011.54 | 16f898dd8ed8279e1055350b4e20666c | too few hosts announce this version | ubuntu:12.04 |
| unseen | SSH-2.0-dropbear_2013.60 | d8c4c5e6e153b1af2e5354aa8c16acee | too few hosts announce this version | ubuntu:14.04 |
| unseen | SSH-2.0-dropbear_2026.92 | 223440d715dad2172ff5f50e87dc537a | too few hosts announce this version | debian:bookworm-slim |
| unseen | SSH-2.0-dropbear_2026.93 | 223440d715dad2172ff5f50e87dc537a | too few hosts announce this version | debian:bookworm-slim |
| unseen | SSH-2.0-paramiko_2.10.0 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.1 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.2 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.3 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.4 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.5 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.10.6 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.11.0 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.11.1 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.4.2 | f945b23acc5455c0ec8afae7ee341a98 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.4.3 | f945b23acc5455c0ec8afae7ee341a98 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.5.0 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.5.1 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.6.0 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.7.0 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.7.1 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.8.0 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.8.1 | 3943d631b90b087bb9e8e755d6f4cfda | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.0 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.1 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.2 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.3 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.4 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_2.9.5 | 38da7a9dfb196c72a7354bb4cdce64d9 | too few hosts announce this version | python:3.8-slim |
| unseen | SSH-2.0-paramiko_3.0.0 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.1.0 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.2.0 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.3.0 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.3.1 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.3.2 | 335240c7e4ea08029ad79fcf794c34ef | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.4.1 | 56a1be8f99f87d129d1879e4bacbbd76 | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_3.5.0 | 90edd2a13bea0aba448bca0557b6ed31 | too few hosts announce this version | python:3.12-slim |
| unseen | SSH-2.0-paramiko_5.0.1 | 48c4b4ca3f96168c5bbbadc362b47dc5 | too few hosts announce this version | python:3.12-slim |
