# Dual-stack clock matching: manual reproduction / verification

Not part of the build or any CI -- this is a standalone harness for
reproducing the bug described in #52 and verifying the fix in this PR,
since the real-world failure depends on transient OS address-selection
behavior and isn't reliably reproducible on demand. Requires Docker only.

It simulates a dual-stack AirPlay client whose RTSP/control connection
(the `T <ip>` registration) uses one address family, while its real PTP
traffic arrives from the *other* family -- the exact mismatch that causes
`nqptp` to never find a master clock.

## Setup

Run all commands from the repository root (the `COPY . /root/nqptp` in
`Dockerfile.nqptp` needs the real source tree as build context).

```sh
docker network create --ipv6 --subnet 172.31.99.0/24 --subnet fd00:99::/64 nqptp-test-net

docker build -t nqptp-test:patched -f contrib/dual-stack-test/Dockerfile.nqptp .
docker build -t nqptp-test:sender -f contrib/dual-stack-test/Dockerfile.sender contrib/dual-stack-test

docker run -d --name nqptp-under-test --network nqptp-test-net nqptp-test:patched -vvv
docker run -d --name sender-sim --network nqptp-test-net nqptp-test:sender
```

## Reproducing the bug (on unpatched nqptp)

Register the client's IPv6 address as the expected timing peer -- this must
run in nqptp's own network namespace, since its control port only accepts
traffic from localhost:

```sh
docker run --rm --network container:nqptp-under-test --entrypoint python3 \
  nqptp-test:sender /test/send_control.py "/nqptp T fd00:99::3"
```

Then send real PTP traffic from the client's *IPv4* address instead
(simulating a system PTP client that doesn't share the RTSP connection's
address-family choice):

```sh
NQPTP_V4=$(docker inspect nqptp-under-test --format \
  '{{(index .NetworkSettings.Networks "nqptp-test-net").IPAddress}}')
docker exec sender-sim python3 /test/send_ptp.py "$NQPTP_V4" TESTCLK1 3 0.1
```

On unpatched `nqptp`, `docker logs nqptp-under-test` shows the raw PTP
packets being received (`ANNC:`/`SYNC:` debug dumps) but no
`announcement seen from ...` line ever appears -- the traffic is silently
discarded because its source address doesn't match the registration.

## Verifying the fix (on this branch)

Repeat the same two commands against a freshly-built patched `nqptp`.
Expect to see, in order:

```
Rebinding pending clock record from fd00:99::3 to observed source 172.31.99.3.
announcement seen from 54455354434c4b31 at 172.31.99.3.
```

To verify the clock is tracked by identity (not just rebound once), send a
second burst from the *other* address family with the same clock tag:

```sh
NQPTP_V6=$(docker inspect nqptp-under-test --format \
  '{{(index .NetworkSettings.Networks "nqptp-test-net").GlobalIPv6Address}}')
docker exec sender-sim python3 /test/send_ptp.py "$NQPTP_V6" TESTCLK1 2 0.1
```

Expect:

```
Known clock 54455354434c4b31 seen at new address fd00:99::3 (was 172.31.99.3). Updating.
```

To verify stale-record garbage collection, register a clock and send no
traffic at all; after 60 seconds `docker logs nqptp-under-test` shows:

```
Expiring stale clock record <N> at <ip>, index <N>, unused for over 60 seconds.
```

## Cleanup

```sh
docker rm -f nqptp-under-test sender-sim
docker network rm nqptp-test-net
```
