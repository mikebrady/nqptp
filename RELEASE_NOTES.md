## Version: 1.1-dev-94-gbaf43f0
#### Significant Changes
* Change clock base to improve stability. You'll need to update Shairport Sync to correspond to it. If you forget to, Shairport Sync will not work properly and will leave a message in the log.
* Improve the ability to maintain synchronisation on a noisy network.

#### Changes
* Don't die if the clock table is full or address list is malformed -- just ignore any extra clocks or invalid ip specs.
* Move to using CLOCK_MONOLITHIC_RAW to avoid NTP effects. Bump interface version.
* Allow a larger amount of negative jitter to be accepted. 
* Only install a service file if there isn't one there already.

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
