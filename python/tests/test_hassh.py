"""Tests for the dependency-free hassh core."""

from __future__ import annotations

import io
import json
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

from hassh import cli, hassh_digest, parse_kexinit
from hassh.kexinit import KexInitError, build_kexinit
from hassh.net import probe, serve
from hassh.pcap import iter_kexinit
from hassh.stream import NotSSH, SSHStreamParser

REPO = Path(__file__).resolve().parents[2]

CLIENT_KEX = "curve25519-sha256,ext-info-c"
SERVER_KEX = "curve25519-sha256,kex-strict-s-v00@openssh.com"
CLIENT_PKT = build_kexinit(CLIENT_KEX, "ssh-ed25519", "aes128-ctr", "hmac-sha2-256", "none,zlib")
SERVER_PKT = build_kexinit(SERVER_KEX, "ssh-ed25519", "aes256-ctr", "hmac-sha2-512", "none")
CLIENT_HASSH = hassh_digest(f"{CLIENT_KEX};aes128-ctr;hmac-sha2-256;none,zlib")
SERVER_HASSH = hassh_digest(f"{SERVER_KEX};aes256-ctr;hmac-sha2-512;none")


def test_readme_example_vectors():
    """The worked examples in the top-level README still hash to the published values."""
    readme = (REPO / "README.md").read_text()
    blocks = [b for b in readme.split("```") if ";" in b and "," in b and "\n" not in b.strip()]
    digests = {hassh_digest(b.strip()) for b in blocks}
    assert "8a8ae540028bf433cd68356c1b9e8d5b" in digests  # Cyberduck 6.7.1 client


def test_parse_kexinit_roundtrip():
    k = parse_kexinit(CLIENT_PKT)
    assert k.kex_algorithms == CLIENT_KEX
    assert k.hassh == CLIENT_HASSH
    assert k.hassh_algorithms == f"{CLIENT_KEX};aes128-ctr;hmac-sha2-256;none,zlib"
    assert parse_kexinit(SERVER_PKT).hassh_server == SERVER_HASSH


@pytest.mark.parametrize("bad", [b"", b"\0\0\0\x0c\x04\x15" + b"\0" * 10, CLIENT_PKT[:40], b"\xff" * 64])
def test_parse_kexinit_rejects_garbage(bad):
    with pytest.raises(KexInitError):
        parse_kexinit(bad)


def test_stream_parser_byte_by_byte_with_preamble():
    parser = SSHStreamParser()
    data = b"Welcome to example\r\nSSH-2.0-Test_1.0 comment\r\n" + SERVER_PKT + b"trailing"
    found = [k for i in range(len(data)) if (k := parser.feed(data[i : i + 1]))]
    assert len(found) == 1 and found[0].hassh_server == SERVER_HASSH
    assert parser.banner == "SSH-2.0-Test_1.0 comment"


def test_stream_parser_skips_ignore_and_debug_before_kexinit():
    ignore = struct.pack(">IB", 12, 6) + b"\x02" + b"\0\0\0\0" + b"\0" * 6
    debug = struct.pack(">IB", 12, 4) + b"\x04\0" + b"\0\0\0\0" + b"x" + b"\0" * 4
    parser = SSHStreamParser()
    assert parser.feed(b"SSH-2.0-Test_1.0\r\n" + ignore + debug + SERVER_PKT).hassh_server == SERVER_HASSH
    # ... but not without end
    with pytest.raises(NotSSH):
        SSHStreamParser().feed(b"SSH-2.0-Test_1.0\r\n" + ignore * 20 + SERVER_PKT)


@pytest.mark.parametrize(
    "data",
    [
        # Text lines may legitimately precede the identification string, but not forever.
        b"GET / HTTP/1.1\r\n" + b"X-Header: value\r\n" * 600,
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",  # TLS ClientHello
    ],
)
def test_stream_parser_rejects_other_protocols(data):
    with pytest.raises(NotSSH):
        SSHStreamParser().feed(data)


# ---------------------------------------------------------------------------
# synthetic captures
# ---------------------------------------------------------------------------
def _tcp(src, dst, sport, dport, seq, flags, payload=b"", v6=False):
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags, 65535, 0, 0) + payload
    if v6:
        ip = struct.pack(">IHBB", 6 << 28, len(tcp), 6, 64)
        ip += socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
        ethertype = 0x86DD
    else:
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0)
        ip += socket.inet_aton(src) + socket.inet_aton(dst)
        ethertype = 0x0800
    return b"\0" * 12 + struct.pack(">H", ethertype) + ip + tcp


def _session(client, server, sport, dport, v6=False, shuffle=False):
    c_data = b"SSH-2.0-TestClient_1\r\n" + CLIENT_PKT
    s_data = b"SSH-2.0-TestServer_2\r\n" + SERVER_PKT
    frames = [
        _tcp(client, server, sport, dport, 999, 0x02, v6=v6),
        _tcp(server, client, dport, sport, 4999, 0x12, v6=v6),
    ]
    # Split each direction into three segments to exercise reassembly.
    c_segs = [(1000 + o, c_data[o : o + 30]) for o in range(0, len(c_data), 30)]
    s_segs = [(5000 + o, s_data[o : o + 50]) for o in range(0, len(s_data), 50)]
    if shuffle:
        c_segs = [c_segs[1], c_segs[0], c_segs[0], *c_segs[2:]]  # out of order + retransmission
        s_segs = s_segs[::-1]
    frames += [_tcp(client, server, sport, dport, seq, 0x18, d, v6=v6) for seq, d in c_segs]
    frames += [_tcp(server, client, dport, sport, seq, 0x18, d, v6=v6) for seq, d in s_segs]
    return frames


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 1536087423 + i, 0, len(frame), len(frame)) + frame
    return out


def _pcapng(frames):
    def block(kind, body):
        body += b"\0" * (-len(body) % 4)
        total = struct.pack("<I", len(body) + 12)
        return struct.pack("<I", kind) + total + body + total

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for frame in frames:
        out += block(6, struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame)
    return out


@pytest.mark.parametrize("writer", [_pcap, _pcapng])
@pytest.mark.parametrize("v6", [False, True])
@pytest.mark.parametrize("shuffle", [False, True])
def test_capture_any_port_reassembly(writer, v6, shuffle):
    client, server = ("2001:db8::1", "2001:db8::2") if v6 else ("10.1.2.3", "192.0.2.9")
    # A non-standard, *lower* client port: direction must come from the SYN.
    frames = _session(client, server, 1022, 8022, v6=v6, shuffle=shuffle)
    events = list(iter_kexinit(io.BytesIO(writer(frames))))
    assert [(e.is_client, e.banner) for e in events] == [
        (True, "SSH-2.0-TestClient_1"),
        (False, "SSH-2.0-TestServer_2"),
    ]
    assert events[0].kexinit.hassh == CLIENT_HASSH
    assert events[1].kexinit.hassh_server == SERVER_HASSH
    assert (events[0].src, events[0].sport, events[0].dport) == (client, 1022, 8022)


def test_capture_without_handshake_uses_port_heuristic():
    frames = _session("10.1.2.3", "192.0.2.9", 50000, 22)[2:]
    events = list(iter_kexinit(io.BytesIO(_pcap(frames))))
    assert [e.is_client for e in events] == [True, False]


def test_cli_json_and_csv(tmp_path):
    capture = tmp_path / "ssh.pcap"
    capture.write_bytes(_pcap(_session("10.1.2.3", "192.0.2.9", 50000, 22)))
    out = tmp_path / "out.json"
    assert cli.main(["-r", str(capture), "-l", "json", "-o", str(out)]) == 0
    client, server = (json.loads(line) for line in out.read_text().splitlines())
    assert client["hassh"] == CLIENT_HASSH and client["client"] == "SSH-2.0-TestClient_1"
    assert client["sourcePort"] == "50000" and client["destinationPort"] == "22"
    assert server["hasshServer"] == SERVER_HASSH and server["sshka"] == "ssh-ed25519"

    out = tmp_path / "out.csv"
    assert cli.main(["-d", str(tmp_path), "-l", "csv", "-o", str(out), "-fp", "server"]) == 0
    header, row = out.read_text().splitlines()
    assert header == cli.CSV_HEADER
    assert f",server,SSH-2.0-TestServer_2,{SERVER_HASSH},1.0," in row


def test_probe_and_listen_roundtrip():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    seen = []
    thread = threading.Thread(target=lambda: seen.extend(serve("127.0.0.1", [port], count=1)))
    thread.start()
    # Our own probe is an SSH "client" that never sends a KEXINIT; play a real one.
    for _ in range(50):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=2)
            break
        except OSError:
            threading.Event().wait(0.05)
    with conn:
        conn.sendall(b"SSH-2.0-TestClient_1\r\n" + CLIENT_PKT)
        parser = SSHStreamParser()
        while parser.kexinit is None:
            parser.feed(conn.recv(4096))
    thread.join(5)
    assert seen[0].kexinit.hassh == CLIENT_HASSH and seen[0].dport == port
    assert parser.banner.startswith("SSH-2.0-hassh")

    # probe() against a canned server
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def canned():
            c, _ = listener.accept()
            with c:
                c.sendall(b"SSH-2.0-TestServer_2\r\n" + SERVER_PKT)
                c.recv(100)

        threading.Thread(target=canned, daemon=True).start()
        event = probe("127.0.0.1", listener.getsockname()[1], timeout=5)
    assert not event.is_client and event.kexinit.hassh_server == SERVER_HASSH

    # a server that waits for the client's KEXINIT before sending its own
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def patient():
            c, _ = listener.accept()
            with c:
                c.sendall(b"SSH-2.0-Patient_1\r\n")
                parser = SSHStreamParser()
                while parser.kexinit is None:
                    parser.feed(c.recv(4096))
                c.sendall(SERVER_PKT)
                c.recv(100)

        threading.Thread(target=patient, daemon=True).start()
        event = probe("127.0.0.1", listener.getsockname()[1], timeout=1)
    assert event.banner == "SSH-2.0-Patient_1" and event.kexinit.hassh_server == SERVER_HASSH


def test_database_files_are_consistent():
    """Every row's fingerprint is the MD5 of its algorithm string."""
    for name, fp in (
        ("hassh_fingerprints", "hassh"),
        ("hasshserver_fingerprints", "hasshServer"),
        ("hasshserver_observed", "hasshServer"),
    ):
        path = REPO / "python" / "hasshGen" / f"{name}.json"
        if not path.exists():
            continue
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        assert rows
        for row in rows:
            assert hassh_digest(row[fp + "Algorithms"]) == row[fp], row


def test_targets_and_profiles_are_consistent():
    gen = REPO / "python" / "hasshGen"
    profiles = json.loads((gen / "profiles.json").read_text())
    for name, profile in profiles.items():
        assert profile["description"] and profile["source"].startswith("https://"), name
        assert bool(profile.get("options")) != bool(profile.get("crypto_policy")), name
    targets = json.loads((gen / "targets.json").read_text())
    for target in targets:
        assert set(target.get("profiles", [])) <= set(profiles), target
    rows = [json.loads(line) for line in (gen / "hasshserver_fingerprints.json").read_text().splitlines()]
    assert {row["configuration"] for row in rows if row.get("configuration")} <= set(profiles)


def test_lab_and_observed_databases_do_not_overlap():
    gen = REPO / "python" / "hasshGen"
    if not (gen / "hasshserver_observed.json").exists():
        pytest.skip("no observed database")
    lab = {json.loads(line)["hasshServer"] for line in (gen / "hasshserver_fingerprints.json").read_text().splitlines()}
    observed = [json.loads(line) for line in (gen / "hasshserver_observed.json").read_text().splitlines()]
    assert observed and not lab & {row["hasshServer"] for row in observed}
    assert all(row["source"] == "observed" and row["serverIdentificationString"] for row in observed)


def test_lookup_labels_profiles_and_observed():
    from hassh import db

    gen = REPO / "python" / "hasshGen"
    if not (gen / "hasshserver_observed.json").exists():
        pytest.skip("no observed database")
    rows = [json.loads(line) for line in (gen / "hasshserver_fingerprints.json").read_text().splitlines()]
    profiled = next(row for row in rows if row.get("configuration"))
    assert any(
        name.endswith(f"[{profiled['configuration']}]") for name in db.lookup(profiled["hasshServer"], server=True)
    )
    observed = json.loads((gen / "hasshserver_observed.json").read_text().splitlines()[0])
    assert db.lookup(observed["hasshServer"], server=True)[0] == observed["serverIdentificationString"] + " (observed)"


def test_harvest_publishes_only_widespread_banners():
    sys.path.insert(0, str(REPO / "python" / "hasshGen"))
    from harvest import harvest

    algos = {name: f"kex-{name};aes128-ctr;hmac-sha2-256;none" for name in "abcd"}
    fp = {name: hassh_digest(value) for name, value in algos.items()}

    def row(name, banner, ips, nets, day="d2"):
        return {"day": day, "banner": banner, "hassh_server": fp[name], "algos": algos[name], "ips": ips, "nets": nets}

    rows = [
        row("a", "SSH-2.0-Lab_1", 5000, 900), row("a", "SSH-2.0-Lab_1", 5000, 900, "d1"),  # already in the lab database
        row("b", "SSH-2.0-Router_7 build9", 300, 80), row("b", "SSH-2.0-Router_7", 300, 80, "d1"),
        row("b", "SSH-2.0-acme-corp-bastion", 60, 1),  # one network: never published
        row("c", "SSH-2.0-OnlyOneDay", 500, 90),  # missing from d1
        row("d", "SSH-2.0-acme-corp-bastion", 400, 2), row("d", "SSH-2.0-acme-corp-bastion", 400, 2, "d1"),
    ]  # fmt: skip
    out, stats = harvest(rows, {fp["a"]}, min_hosts=20, min_nets=10, min_share=0.1)
    assert [r["hasshServer"] for r in out] == [fp["b"]]
    assert out[0]["serverIdentificationString"] == "SSH-2.0-Router_7" and out[0]["alsoSeenAs"] == []
    assert "acme" not in json.dumps(out) and "_hosts" not in out[0]
    assert abs(stats["lab"] - 5000 / 6260) < 1e-9


def test_real_capture():
    """tcpdump capture of OpenSSH 10.0 (Alpine 3.22) talking to itself on port 2022."""
    with (Path(__file__).parent / "data" / "openssh_10.0_loopback.pcap").open("rb") as fh:
        client, server = iter_kexinit(fh)
    assert client.is_client and client.banner == "SSH-2.0-OpenSSH_10.0" and client.dport == 2022
    assert client.kexinit.hassh == "eeca2460550b9ded084ecf2f70a75356"
    assert not server.is_client and server.kexinit.hassh_server == "671c5858369db8e0a60108d866bbf8ec"


def test_update_targets_finds_only_newer_releases():
    sys.path.insert(0, str(REPO / "python" / "hasshGen"))
    import update_targets as ut

    targets = [
        {
            "recipe": "openssh-src",
            "image": "debian",
            "image_ver": "bookworm-slim",
            "version": "9.9p2",
            "profiles": ["x"],
        },
        {"recipe": "openssh-src", "image": "debian", "image_ver": "bookworm-slim", "version": "10.0p1"},
        {"recipe": "go-ssh", "image": "golang", "image_ver": "1.24-alpine", "version": "v0.41.0"},
        {"recipe": "apk-openssh", "image": "alpine", "image_ver": "3.9"},
        {"recipe": "apk-openssh", "image": "alpine", "image_ver": "3.24"},
        {"recipe": "apk-dropbear", "image": "alpine", "image_ver": "3.24"},
        {"recipe": "apk-openssh", "image": "alpine", "image_ver": "edge"},
        {"recipe": "apt-openssh", "image": "debian/eol", "image_ver": "stretch-slim"},
        {"recipe": "apt-openssh", "image": "debian", "image_ver": "trixie-slim"},
        {"recipe": "openwrt-dropbear", "image": "openwrt", "image_ver": "23.05.5", "platform": "linux/amd64"},
        {"recipe": "openwrt-dropbear", "image": "openwrt", "image_ver": "24.10.1", "platform": "linux/amd64"},
    ]
    listing = "openssh-9.8p1.tar.gz openssh-10.0p1.tar.gz openssh-10.0p2.tar.gz openssh-10.1p1.tar.gz.asc"
    new = ut.new_upstream(targets, "openssh-src", listing)
    assert [t["version"] for t in new] == ["10.0p2", "10.1p1"] and "profiles" not in new[0]
    assert [t["version"] for t in ut.new_upstream(targets, "go-ssh", "v0.9.0\nv0.42.0\nv0.42.0-rc.1\n")] == ["v0.42.0"]
    tags = ["3.25", "3.25.1", "3.24", "3.8", "edge", "latest", "20260101"]
    assert [(t["recipe"], t["image_ver"]) for t in ut.new_images(targets, "alpine", tags)] == [
        ("apk-openssh", "3.25"),
        ("apk-dropbear", "3.25"),
    ]
    tags = ["trixie-slim", "stretch-slim", "stable-slim", "duke-slim", "trixie-20260101-slim"]
    assert [t["image_ver"] for t in ut.new_images(targets, "debian", tags)] == ["duke-slim"]
    listing = '<a href="23.05.5/"> <a href="23.05.6/"> <a href="24.10.1/"> <a href="25.12.0/"> <a href="19.07.10/">'
    assert [t["image_ver"] for t in ut.new_openwrt(targets, listing)] == ["23.05.6", "25.12.0"]
    ut.insert(targets, new[0])
    assert targets[2]["version"] == "10.0p2"


def test_harvest_prune_and_changed_only(tmp_path):
    sys.path.insert(0, str(REPO / "python" / "hasshGen"))
    import harvest

    import hasshgen

    rows = [{c: "" for c in harvest.COLUMNS} | {"hasshServer": h, "alsoSeenAs": []} for h in ("a", "b")]
    harvest.write(tmp_path / "observed", rows)
    assert harvest.prune(tmp_path / "observed", {"b"}) == 1
    assert [json.loads(line)["hasshServer"] for line in (tmp_path / "observed.json").read_text().splitlines()] == ["a"]

    def row(version, fingerprint):
        return {
            "image": "ubuntu", "imageVersion": "24.04", "sshServer": "openssh-server", "sshServerVersion": version,
            "serverIdentificationString": "SSH-2.0-x", "hasshServer": fingerprint, "hasshVersion": "1.0",
            "hasshServerAlgorithms": "",
        }  # fmt: skip

    base = tmp_path / "db"
    assert hasshgen.update_db(base, [row("1", "f1")], "server") == (1, 1)
    assert hasshgen.update_db(base, [row("2", "f1")], "server", changed_only=True) == (0, 1)
    assert hasshgen.update_db(base, [row("3", "f2")], "server", changed_only=True) == (1, 2)
