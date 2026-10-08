# Dual-stack clock matching: manual reproduction / verification

Not part of the build or any CI -- this is a standalone harness for
reproducing the bug described in #52 and verifying the fix in this PR,
since the real-world failure depends on transient OS address-selection
behavior and isn't reliably reproducible on demand. Requires Docker and
Docker Compose only.

It simulates a dual-stack AirPlay client whose RTSP/control connection
(the `T <ip>` registration) uses one address family, while its real PTP
traffic arrives from the *other* family -- the exact mismatch that causes
`nqptp` to never find a master clock. The `nqptp` and `sender` containers
get fixed addresses (`172.31.99.2`/`fd00:99::2` and `172.31.99.3`/`fd00:99::3`
respectively) so the commands below don't need to look anything up.

Run everything from the repository root.

## Setup

```sh
docker compose -f contrib/dual-stack-test/docker-compose.yml up -d --build
```

## Reproducing the bug (on unpatched nqptp)

Register the client's IPv6 address as the expected timing peer -- the
`control` service shares nqptp's network namespace, since its control port
only accepts traffic from localhost:

```sh
docker compose -f contrib/dual-stack-test/docker-compose.yml exec control \
  python3 /test/send_control.py "/nqptp T fd00:99::3"
```

Then send real PTP traffic from the client's *IPv4* address instead
(simulating a system PTP client that doesn't share the RTSP connection's
address-family choice):

```sh
docker compose -f contrib/dual-stack-test/docker-compose.yml exec sender \
  python3 /test/send_ptp.py 172.31.99.2 TESTCLK1 3 0.1
```

On unpatched `nqptp`, `docker compose -f contrib/dual-stack-test/docker-compose.yml logs nqptp`
shows the raw PTP packets being received (`ANNC:`/`SYNC:` debug dumps) but
no `announcement seen from ...` line ever appears -- the traffic is
silently discarded because its source address doesn't match the
registration.

## Verifying the fix (on this branch)

Repeat the same two commands above (this harness builds `nqptp` from the
checked-out source, so it already includes the fix on this branch).
Expect to see, in order:

```
Rebinding pending clock record from fd00:99::3 to observed source 172.31.99.3.
announcement seen from 54455354434c4b31 at 172.31.99.3.
```

To verify the clock is tracked by identity (not just rebound once), send a
second burst from the *other* address family with the same clock tag:

```sh
docker compose -f contrib/dual-stack-test/docker-compose.yml exec sender \
  python3 /test/send_ptp.py fd00:99::2 TESTCLK1 2 0.1
```

Expect:

```
Known clock 54455354434c4b31 seen at new address fd00:99::3 (was 172.31.99.3). Updating.
```

To verify stale-record garbage collection, register a clock and send no
traffic at all; after 60 seconds the nqptp log shows:

```
Expiring stale clock record <N> at <ip>, index <N>, unused for over 60 seconds.
```

## Cleanup

```sh
docker compose -f contrib/dual-stack-test/docker-compose.yml down
```
