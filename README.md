# NQPTP – Not Quite PTP
The `nqptp` daemon monitors PTP traffic. Briefly, `nqptp` monitors the times of any [PTP](https://en.wikipedia.org/wiki/Precision_Time_Protocol) clocks – up to 32 – it sees on ports 319 and 320. It maintains records for each clock, identified by its Clock ID and IP. Information about the *master clock* is provided in a [POSIX shared memory](https://pubs.opengroup.org/onlinepubs/007908799/xsh/shm_open.html) interface at `/nqptp`. Here are details of the interface:
```c
struct shm_structure {
  pthread_mutex_t shm_mutex; // for safely accessing the structure
  uint16_t version;          // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint32_t flags;            // unused
  uint64_t master_clock_id;  // the current master clock
  char master_clock_ip[64];  // the IP of the current master clock
  uint64_t local_time;       // the time when the offset was calculated
  uint64_t local_to_master_time_offset; // add this to the local time to get master clock time
};
```

# Installation
```
$ git clone git@github.com:mikebrady/nqptp.git
$ cd nqptp
$ autoreconf -fi
$ ./configure
$ make
# make install
```
The `make install` creates the `nqptp` group and installs a `systemd` startup script. You should enable it and start it in the normal way. Note that `nqptp` must run in `root` mode to be able to access ports 319 and 320.

# Notes
A unix group called `nqptp` is created by the `make install` step. Members of this group have write access to the shared memory interface.
If you wish to use the shared mutex to ensure records are not altered while you are accessing them, you should open your side of the shared memory interface with read-write permission. Be aware that while your program has the mutex lock, it can halt `nqptp`, so keep any activity while you have the lock very short and very simple, e.g. copying it to local memory. 

Clock records not updated for a period are deleted.

Since `nqptp` uses ports 319 and 320, it can not coexist with any other user of those ports, such as full PTP service daemons.

# Known Issues
* At present, `nqptp` does not take advantage of hardware timestamping.
* The daemon is Linux only, and has been developed and tested on a `systemd` Linux only.

# Things Can Change
The `nqptp` daemon is under active development and, consequently, everything here can change, possibly very radically.

# NQPTP is not PTP!
`nqptp` uses just a part of the [IEEE 1588-2008](https://standards.ieee.org/standard/1588-2008.html) protocol. It is not a PTP clock of any kind.
