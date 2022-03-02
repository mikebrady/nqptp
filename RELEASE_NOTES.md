## Version: 1.1-dev-124-g9a57e77
***Pesky Change You Can't Ignore***

A change has been made the `nqptp` `systemd` service file, so before updating, please remove the existing service file with the following command:
```
# rm /usr/local/lib/systemd/system/nqptp.service
```
**Enhancement**
* Always create a new SHM interface for every new shm address provided.
* Remove redundant code.
* Add a few debug messages.
* Enhance the service record to define the service provided.
* Quieten some chatty debug messages.

## Version: 1.1-dev-117-g7e3c2b7
**Dedicated client interfaces**
NQPTP has gone multi-client. Clients now specify a named SMI interface through which they can specify their own timing peers and through which PTP information for that group of clock peers is returned. Thus, multiple clients (e.g. multiple instances of Shairport Sync) can maintain synchrnoisation with their own individual clock groups.

## Version: 1.1-dev-108-ga378f07
**Enhancement**
* Ensure the shared memory interface is updated when mastership is removed.

## Version: 1.1-dev-107-g811524b
**Enhancement**
* Further simplify things by turning off history completely and by discarding any mastership history prior to becoming part of a (possibly new) timing peer list.

## Version: 1.1-dev-104-gd78c84a
**Enhancement**
* Make `nqptp` tolerant of longer gaps in the reception of messages from the master clock -- up to 300 seconds. This may be overkill, since messages are meant to arrive 8 times per second, but experience shows that rather long gaps can indeed occur.

## Version: 1.1-dev-102-gf678f82
**Enhancement**
* Try to improve the reliability of restarting a "silent clock" device, e.g. an Apple Silicon Mac or an AppleTV. Also turn off history (mostly) to see if we can make things simpler.

## Version: 1.1-dev-74-gf713183
**Enhancement**
* Add code to activate a PTP clock that has become effectively silent. This can happen to a PTP clock on an Apple Silicon Mac after it has been woken from sleep. It may happen elsewhere.
The new code begins and then rapidly terminates a clock mastership negotiation, and this causes the clock to become active.
This 'silent clock' is unexpected behaviour and may be a bug.

## Version: 1.1-dev-51-g812326a
***Pesky Change You Can't Ignore***

A change has been made to where the `nqptp` `systemd` service file is placed. If you are updating from a previous version of `nqptp`, please do the following before you update:
1. Disable the `nqptp` service as follows:
```
# systemctl disable nqptp
```
2. Remove the service file `nqptp.service` from the directory `/lib/systemd/system` (you'll need superuser privileges). A new service file will be installed in the correct location -- `/usr/local/lib/systemd/system` in Ubuntu 20.04 and Raspbian OS (Buster) -- during the `# make install` step.

After updating, re-enable the `nqptp` service as follows:
```
# systemctl enable nqptp
```

**Enhancement**
* Further modify `install-exec-hook` to also use the standard `$(libdir)` variable instead of a fixed location. Thanks to [FW](https://github.com/fwcd).

## Version: 1.1-dev-44-g827e624
* Modify `install-exec-hook` to use the standard `$DESTDIR` variable instead of the fixed location `/lib/systemd/`. This is to facilitate build environments that install into a separate directory (e.g. cross-compiling environments). Thanks to [HiFiBerry](https://github.com/hifiberry).

## Version: 1.1-dev-40-g6111d69
* Fix a crashing bug. Thanks to [ste94pz](https://github.com/ste94pz) for reporting and debugging.

## Version: 1.1-dev-36-g880b424
* Initial public version.
