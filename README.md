# nqptp
Not Quite a PTP Daemon, `nqptp` monitors PTP traffic.

# What is nqptp for?
Briefly, `nqptp` monitors the times of any PTP clocks -- up to 32 -- it sees on port 319/320. It maintains a record for each clock, identified by its Clock ID and IP. This information is provided via a Posix shared memory interface at `/nqptp` . Here are details of the interface:
```c
struct clock_source {
  char ip[64]; // 64 is nicely aligned and bigger than INET6_ADDRSTRLEN (46)
  uint64_t clock_id;
  uint64_t reserved;
  uint64_t source_time;                 // the time at the source at
  uint64_t local_time;                  // the local time when the source time is valid
  uint64_t local_to_source_time_offset; // add this to the local time to get source time
  int flags;                            // not used yet
  int valid;                            // this entry is valid
};

struct shm_structure {
  pthread_mutex_t shm_mutex;    // for safely accessing the structure
  uint16_t size_of_clock_array; // check this is equal to MAX_SHARED_CLOCKS
  uint16_t version;             // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint32_t flags;
  struct clock_source clocks[MAX_SHARED_CLOCKS];
};
```
Upon installation, a unix group called `nqptp` is created. Members of that group will have write access to this shared memory and so can use the `shm_mutex` for safe access to the information. Be aware that while your program has the lock, it can halt `nqptp`, so keep any activity while you have the lock very short and very simple, e.g. making a copy of it to local memory. 

# Installation
```
$ autoreconf -fi
$ ./configure
$ make
# make install
```
The `make install` creates the `nqptp` group and installs a `systemd` startup script. You should enable it and start it in the normal way. Note that `nqptp` must run in `root` mode to be able to access ports 319 and 320.

# Notes
Since `nqptp` uses ports 319 and 320, it can not coexist with any other user of those ports, such as full PTP service daemons.

# Known Issues
1 Old clock records are not garbage-collected, so once it has seen 32 different clock/ip combinations, it fills up. This will be fixed real soon now.
2 At present, `nqptp` does not take advantage of hardware timestamping. It will soon.
