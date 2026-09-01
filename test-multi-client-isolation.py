#!/usr/bin/env python3
"""Regression test: one nqptp client's control messages must not disturb another's.

This is the bug that multi-client support exists to prevent. Before per-client
state was restored, nqptp parsed the shared memory interface name off the front
of every control message and then discarded it, keeping ONE clock table and ONE
shared memory region for the whole host. A bare "T" (stop timing) -- which
shairport-sync sends when a room leaves an AirPlay 2 group -- ran "delete all
the clocks" and zeroed the master clock that every OTHER instance on the box was
still reading. Those instances stopped playing and never recovered.

The test drives nqptp's control port directly, so it needs no AirPlay sender and
no PTP traffic. Each client's master clock is poisoned with a distinct value by
mmapping its region, standing in for a clock it had acquired. Then one client
sends the bare "T" a departing room sends, and we check who got cleared.

    sudo ./test-multi-client-isolation.py [./nqptp]

Exits non-zero on failure. Run it against a pre-fix binary and it fails at
"kitchen's master clock survived", which is the regression itself.
"""
import mmap
import os
import socket
import struct
import subprocess
import sys
import time

CONTROL_PORT = 9000
SHM_SIZE = 72          # sizeof(struct shm_structure)
VERSION_OFF = 0        # uint16_t version
MAIN_OFF = 8           # shm_structure_set main
SECONDARY_OFF = 40     # shm_structure_set secondary
MASTER_CLOCK_ID_OFF = 0  # first field of a shm_structure_set
EXPECTED_SMI_VERSION = 10

KITCHEN = "/nqptp-test-kitchen"
FOYER = "/nqptp-test-foyer"
PEER_IP = "192.168.1.209"

failures = []


def check(ok, description):
    print("  %s  %s" % ("ok  " if ok else "FAIL", description))
    if not ok:
        failures.append(description)
    return ok


def send(sock, message):
    # shairport-sync sends the interface name, a space, then the command.
    sock.sendto(message.encode() + b"\0", ("127.0.0.1", CONTROL_PORT))
    time.sleep(0.25)


def shm_path(name):
    return "/dev/shm/" + name.lstrip("/")


def open_region(name):
    fd = os.open(shm_path(name), os.O_RDWR)
    try:
        return mmap.mmap(fd, SHM_SIZE)
    finally:
        os.close(fd)


def read_master_clock(name, which=MAIN_OFF):
    with open(shm_path(name), "rb") as f:
        data = f.read(SHM_SIZE)
    return struct.unpack_from("<Q", data, which + MASTER_CLOCK_ID_OFF)[0]


def read_version(name):
    with open(shm_path(name), "rb") as f:
        return struct.unpack_from("<H", f.read(SHM_SIZE), VERSION_OFF)[0]


def poison(name, value):
    """Stand in for a master clock this client had acquired from real PTP traffic."""
    region = open_region(name)
    for which in (MAIN_OFF, SECONDARY_OFF):
        struct.pack_into("<Q", region, which + MASTER_CLOCK_ID_OFF, value)
    region.flush()
    region.close()


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./nqptp"
    if os.geteuid() != 0:
        sys.exit("must run as root: nqptp binds PTP ports 319/320 and creates shared memory")

    for name in (KITCHEN, FOYER):
        if os.path.exists(shm_path(name)):
            os.unlink(shm_path(name))

    daemon = subprocess.Popen([binary, "-vv"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(0.6)
        if daemon.poll() is not None:
            sys.exit("nqptp exited immediately:\n" + daemon.stdout.read().decode())

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print("two clients, each starting timing and playing:")
        for name in (KITCHEN, FOYER):
            send(sock, "%s T %s" % (name, PEER_IP))  # start timing on a peer
            send(sock, "%s B" % name)                # play

        both_exist = all(os.path.exists(shm_path(n)) for n in (KITCHEN, FOYER))
        check(both_exist, "each client got its own named shared memory interface")
        if not both_exist:
            # A pre-fix nqptp ignores the interface name and keeps one region for
            # the whole host. Show what that costs rather than just bailing out.
            shared = "/nqptp"
            if os.path.exists(shm_path(shared)):
                poison(shared, 0xAAAAAAAAAAAAAAAA)
                send(sock, "%s T" % FOYER)  # foyer leaves the group
                clobbered = read_master_clock(shared) == 0
                print("     -> this nqptp keeps ONE region, %s, for every client." % shared)
                print("     -> foyer's departure %s the master clock kitchen was reading."
                      % ("ZEROED" if clobbered else "left"))
            sock.close()
            return

        check(read_version(KITCHEN) == EXPECTED_SMI_VERSION and
              read_version(FOYER) == EXPECTED_SMI_VERSION,
              "both regions carry SMI version %d" % EXPECTED_SMI_VERSION)

        poison(KITCHEN, 0xAAAAAAAAAAAAAAAA)
        poison(FOYER, 0xBBBBBBBBBBBBBBBB)
        check(read_master_clock(KITCHEN) == 0xAAAAAAAAAAAAAAAA and
              read_master_clock(FOYER) == 0xBBBBBBBBBBBBBBBB,
              "the two regions are distinct memory")

        # This is the exact message a room sends as it leaves a group.
        print("foyer leaves the group (bare \"T\"):")
        send(sock, "%s T" % FOYER)

        check(read_master_clock(FOYER) == 0,
              "foyer's own master clock was cleared, as it asked")
        check(read_master_clock(KITCHEN) == 0xAAAAAAAAAAAAAAAA,
              "kitchen's master clock survived -- THE REGRESSION")
        check(read_master_clock(KITCHEN, SECONDARY_OFF) == 0xAAAAAAAAAAAAAAAA,
              "kitchen's secondary record survived too")

        # An "E" (stop) from one client must likewise leave the other alone.
        poison(FOYER, 0xCCCCCCCCCCCCCCCC)
        print("kitchen stops (\"E\"):")
        send(sock, "%s E" % KITCHEN)
        check(read_master_clock(FOYER) == 0xCCCCCCCCCCCCCCCC,
              "foyer untouched by kitchen's stop")

        sock.close()
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
        for name in (KITCHEN, FOYER):
            if os.path.exists(shm_path(name)):
                os.unlink(shm_path(name))


if __name__ == "__main__":
    main()
    if failures:
        print("\nFAILED: %d check(s): %s" % (len(failures), "; ".join(failures)))
        sys.exit(1)
    print("\nALL MULTI-CLIENT ISOLATION CHECKS PASSED")
