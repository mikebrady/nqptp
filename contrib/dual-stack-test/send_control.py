#!/usr/bin/env python3
# Sends an nqptp control command over UDP to localhost:9000, exactly as
# shairport-sync's ptp-utilities.c does. Must run in the same network
# namespace as nqptp (the control socket is bound to "localhost" only).
import socket
import sys

cmd = sys.argv[1]  # e.g. "/nqptp T fd00:99::20" or "/nqptp T"
# nqptp unconditionally nulls out the last received byte (it assumes a
# trailing delimiter), so pad with one sacrificial character.
payload = (cmd + "\n").encode()
for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.sendto(payload, (addr, 9000))
        s.close()
    except OSError as e:
        print(f"skip {addr}: {e}", file=sys.stderr)
print(f"sent: {cmd!r}")
