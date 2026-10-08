#!/usr/bin/env python3
# Crafts and sends minimal but valid PTP Announce/Sync messages to a given
# nqptp instance, from this host's own source address (whichever family
# that happens to be) -- used to simulate a dual-stack client whose real
# PTP traffic arrives from a different address family than the one
# registered via the control port.
import socket
import struct
import sys
import time

# struct ptp_common_message_header (packed, network byte order), 34 bytes
HEADER_FMT = ">BBHBBHQI8sHHBB"
# struct ptp_announce extra part, 30 bytes
ANNOUNCE_FMT = ">10sHBBIB8sHB"
# struct ptp_sync extra part, 10 bytes
SYNC_FMT = ">10s"

ANNOUNCE_TYPE = 0xB
SYNC_TYPE = 0x0


def clock_id_bytes(tag: str) -> bytes:
    b = tag.encode().ljust(8, b"\0")[:8]
    return b


def build_header(msg_type: int, body_len: int, clock_id: bytes, seq: int) -> bytes:
    total_len = 34 + body_len
    return struct.pack(
        HEADER_FMT,
        0x10 | msg_type,  # transportSpecific=1, messageID=msg_type
        0x02,  # version
        total_len,
        0,  # domainNumber
        0,  # reserved
        0x0408,  # flags
        0,  # correctionField
        0,  # reserved_l
        clock_id,
        1,  # sourcePortID
        seq,
        5,  # controlField
        0,  # logMessagePeriod
    )


def build_announce(clock_id: bytes, seq: int) -> bytes:
    body = struct.pack(
        ANNOUNCE_FMT,
        b"\0" * 10,  # originTimestamp
        37,  # currentUtcOffset
        0,  # reserved1
        248,  # grandmasterPriority1
        0x00800000,  # grandmasterClockQuality (class 128-ish placeholder)
        248,  # grandmasterPriority2
        clock_id,  # grandmasterIdentity == clock_id (single-clock scenario)
        0,  # stepsRemoved
        0xA0,  # timeSource
    )
    return build_header(ANNOUNCE_TYPE, len(body), clock_id, seq) + body


def build_sync(clock_id: bytes, seq: int) -> bytes:
    body = struct.pack(SYNC_FMT, b"\0" * 10)
    return build_header(SYNC_TYPE, len(body), clock_id, seq) + body


def send(target_host: str, clock_tag: str, count: int, delay: float):
    clock_id = clock_id_bytes(clock_tag)
    # Announce -> general port 320, Sync -> event port 319 (standard PTP convention).
    # nqptp's dispatch loop requires sender_port == receiver_port (319->319 or
    # 320->320), so the source port must be explicitly bound, not left ephemeral.
    ann_infos = socket.getaddrinfo(target_host, 320, 0, socket.SOCK_DGRAM)
    sync_infos = socket.getaddrinfo(target_host, 319, 0, socket.SOCK_DGRAM)
    ann_family, ann_socktype, _, _, ann_addr = ann_infos[0]
    sync_family, sync_socktype, _, _, sync_addr = sync_infos[0]
    ann_sock = socket.socket(ann_family, ann_socktype)
    sync_sock = socket.socket(sync_family, sync_socktype)
    ann_sock.bind(("", 320))
    sync_sock.bind(("", 319))
    for i in range(count):
        ann_sock.sendto(build_announce(clock_id, i + 1), ann_addr)
        sync_sock.sendto(build_sync(clock_id, i + 1), sync_addr)
        time.sleep(delay)
    ann_sock.close()
    sync_sock.close()
    print(f"sent {count} announce+sync pairs to {target_host} as clock {clock_tag!r} "
          f"from local family {ann_family}")


if __name__ == "__main__":
    target_host = sys.argv[1]
    clock_tag = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.3
    send(target_host, clock_tag, count, delay)
