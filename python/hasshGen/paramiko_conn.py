#!/usr/bin/env python
"""Start a paramiko client transport so that it sends its KEXINIT."""

import sys

import paramiko

hostname, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 22

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(
        hostname,
        port=port,
        username="user",
        password="pass",
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
except Exception as exc:  # the collector hangs up after the KEXINIT
    print("expected failure: %r" % (exc,))
finally:
    client.close()
