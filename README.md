# nqptp
*Not Quite a PTP Daemon*, `nqptp` monitors PTP traffic. Briefly, `nqptp` monitors the times of any [PTP](https://en.wikipedia.org/wiki/Precision_Time_Protocol) clocks -- up to 32 -- it sees on ports 319 and 320. It maintains a record for each clock, identified by its Clock ID and IP. This information is provided via a [POSIX shared memory](https://pubs.opengroup.org/onlinepubs/007908799/xsh/shm_open.html) interface at `/nqptp`. Here are details of the interface:
```c
struct clock_source {
  char ip[64];                           // the IP the clock information is coming from
  uint64_t clock_id;
  uint64_t reserved;
  uint64_t source_time;                 // the time at the source
  uint64_t local_time;                  // the local time for which when the source time is valid
  uint64_t local_to_source_time_offset; // add this to the local time to get source time
  int flags;                            // not used yet
  int valid;                            // true if this entry is valid
};

struct shm_structure {
  pthread_mutex_t shm_mutex;    // for safely accessing the structure
  uint16_t size_of_clock_array; // should contain the value MAX_SHARED_CLOCKS
  uint16_t version;
  uint32_t flags;
  struct clock_source clocks[MAX_SHARED_CLOCKS];
};
```

# Installation
```
$ autoreconf -fi
$ ./configure
$ make
# make install
```
The `make install` creates the `nqptp` group and installs a `systemd` startup script. You should enable it and start it in the normal way. Note that `nqptp` must run in `root` mode to be able to access ports 319 and 320.

# Notes
A unix group called `nqptp` is created by the `make install` step. Members of this group have write access to the shared memory interface.
If you wish to use the shared mutex to ensure records are not altered while you are accessing them, you should open your side of the shared memory interface with read-write permission. Be aware that while your program has the mutex lock, it can halt `nqptp`, so keep any activity while you have the lock very short and very simple, e.g. copying it to local memory. 

The `source_time` and `local_to_source_time_offset` values are averaged over up to 480 samples. Since samples should be received at the rate of eight per second,
the values are averaged should be dropped the previous minute.

Clock records not updated for a period are deleted.

Since `nqptp` uses ports 319 and 320, it can not coexist with any other user of those ports, such as full PTP service daemons.

# Known Issues
* At present, `nqptp` does not take advantage of hardware timestamping.

# Things Can Change!
The `nqptp` daemon is under active development and, consequently, everything here can change, possibly very radically.
