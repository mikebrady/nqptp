# NQPTP – Not Quite PTP
Briefly, `nqptp` monitors timing data from any [PTP](https://en.wikipedia.org/wiki/Precision_Time_Protocol) clocks – up to 32 – it sees on ports 319 and 320. It maintains records for each clock, identified by Clock ID and IP.

A timing peer list can be sent to `nqptp` over port 9000. The list consists of the letter `T` followed by a space-separated list of the IP numbers of the timing peers. The list replaces any existing timing peer list.

Information about the timing peer list's *master clock* is provided via a [POSIX shared memory](https://pubs.opengroup.org/onlinepubs/007908799/xsh/shm_open.html) interface at `/nqptp`. 


Here are details of the interface:
```c
struct shm_structure {
  pthread_mutex_t shm_mutex; // for safely accessing the structure
  uint16_t version;          // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint32_t flags;            // unused
  uint64_t master_clock_id;  // the current master clock
  char master_clock_ip[64];  // the IP of the current master clock
  uint64_t local_time;       // the time when the offset was calculated
  uint64_t local_to_master_time_offset; // add this to the local time to get master clock time
  uint64_t master_clock_start_time;     // this is when the master clock became master
};
```

# Installation

#### Please use `git`!
As you probably know, you can download the repository in two ways: (1) using `git` to clone it  -- recommended -- or (2) downloading the repository as a ZIP archive. Please us the `git` method. The reason it that when you use `git`,
the build process can incorporate the git build information in the version string you get when you execute the command `$ nqptp -V`.
This will be very useful for identifying the exact build if you are making comments or bug reports. Here is an example:
```
Version with git build information:
Version: 1.1-dev-24-g0c00a79. Shared Memory Interface Version: 5.

Version without git build information:
Version: 1.1-dev. Shared Memory Interface Version: 5.
```
### Build and Install
```
$ git clone git@github.com:mikebrady/nqptp.git
$ cd nqptp
$ autoreconf -fi
$ ./configure
$ make
# make install
```
The `make install` installs a `systemd` startup script. You should enable it and start it in the normal way. Note that `nqptp` must run in `root` mode to be able to access ports 319 and 320.

# Notes
If you wish to use the shared mutex to ensure records are not altered while you are accessing them, you should open your side of the shared memory interface with read-write permission. Be aware that while your program has the mutex lock, it is in a "critical region" where it can halt `nqptp`, so keep any activity while you have the lock very short and very simple, e.g. copying it to local memory. 

Clock records not updated for a period are deleted.

Since `nqptp` uses ports 319 and 320, it can not coexist with any other user of those ports, such as full PTP service daemons.

# Known Issues
* `nqptp` has not been checked or audited for security issues. Note that it must run in `root` mode.
* It's probably buggy!
* `nqptp` does not take advantage of hardware timestamping.

# Things Can Change
The `nqptp` daemon is under active development and, consequently, everything here can change, possibly very radically.

# NQPTP is not PTP!
`nqptp` uses just a part of the [IEEE 1588-2008](https://standards.ieee.org/standard/1588-2008.html) protocol. It is not a PTP clock.
