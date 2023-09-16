## Version: 1.2.4
This is an important security update. The Shared Memory Interface of the updated NQPTP is now 10, i.e. `smi10`:
```
$ nqptp -V
Version: 1.2.4. Shared Memory Interface Version: smi10.
```
1. When updating NQPTP on Linux, be sure to remove the old service file as directed in the [README](https://github.com/mikebrady/nqptp/blob/main/README.md#remove-old-service-files).
2. You must update Shairport Sync to ensure that it's Shared Memory Interface version is also 10 in order to be compatible with this NQPTP update.
3. Having completed both updates and installations, remember to restart NQPTP first and then restart Shairport Sync.

**Security Updates**
* A crashing bug in NQPTP has been fixed.
* The communications protocol used between NQPTP and Shairport Sync has been revised and made more resilient to attempted misuse.
* In Linux systems, NQPTP no longer runs as `root` -- instead it is installed at the `# make install` stage to run as the restriced user `nqptp`, with access to ports 319 and 320 set by the installer via the `setcap` utility.

## Version: 1.2
* The protocol that Shairport Sync and NQPTP use to communicate with one another has been updated to reflect changes in NQPTP's operation. Please update both NQPTP and Shairport Sync so that they both use the same Shared Memory Interface Version. 

**Enhancements**
* Enable NQPTP to respond to information about the state of the player -- whether is is playing, stopped or paused. The "B" command is a message that the client -- which generates the clock -- is about to start playing. The "E" command signifies that the client has stopped playing and that the clock may shortly sleep. The "P" command signifies that play has paused (buffered audio only). The clock seems to stay running in this state.
This is important because the clock from the source can stop or run slow when the source is not actively playing. This arrangement seems to be much more resilient than having NQPTP try to detect when a clock is stopped or running slow. It also allows the code to be  simplified.

## Version: 1.1-dev-207-ge14575b
**Bug Fix**
* Due to a bug, the ports used by NQPTP -- ports 319, 320 and 9000 -- had to be available on all IP protocols on the system. For example, if IPv6 and IPv4 were available on the system and a port could be opened on IPv4 but not on IPv6 , Shairport Sync would fail. This has been fixed. As before, ports will be opened on all IP protocols available, but only one needs to be successfully opened. Many thanks to [Ferdynand Naczynski](https://github.com/nipsufn) for their detective work and for developing a fix.

## Version: 1.1-dev-199-g2b5490c
**Bug Fixes**
* Use the previous offset if a negative jitter for the first period.
* Fix a misleading comment.

**Enhancements**
* Tune the weights of offset additions and reductions to further reduce the offset errors in the initial adjustment period.

## Version: 1.1-dev-196-g9fc0501
**Enhancement**
* Finally (!) the suggestion made by [the0u](https://github.com/th0u) in [Issue #14]() has been acted upon and the suggested modifications made so that NQPTP will only listen to connections made to port 9000 coming from `localhost`. Thanks to [the0u](https://github.com/th0u) for the suggestion and the code. Thanks to [herrernst](https://github.com/herrernst) for the reminder!

## Version: 1.1-dev-195-g93f1e8a

**Enhancement**
* NQPTP has been simplified and is more resilient to adverse network conditions.

## Version: 1.1-dev-175-g264805d
Weird build numbers.

**Bug Fix**
* Only try to start a silent clock if no follow_ups have _ever_ been received from it.

## Version: 1.1-dev-168-g3444047
***Pesky Changes You Can't Ignore***

* **Important**. The Shared Memory Interface protocol that Shairport Sync and NQPTP use to communicate with one another has been updated to reflect changes in NQPTP's operation. Please update both NQPTP and Shairport Sync so that they both use the same version number -- 8.

**FYI**

* The ability to handle multiple instances of AirPlay-2-capable Shairport Sync on the same system has been removed. It seems that clients can not use this facility.

**Enhancements**
* Greatly simplify NQPTP by only monitoring PTP information coming from the client, ignoring all other PTP information.
* In addition to trying to restart a clock that is silent, also send a restart to a clock if the clock's grandmaster appears to have stopped.

## Version: 1.1-dev-186-g4e54f1b
**Bug Fixes**
* Reorder system header files includes to fix a compilation error.

## Version: 1.1-dev-166-g46a9f1b
* Update the wording in the INSTALL document to match the wording generated at the `autoreconf -fi` stage, so that `git` doesn't flag an altered document. Thanks to [David Leibovic](https://github.com/dasl-) for bringing this to notice.

## Version: 1.1-dev-161-g353093a
**Bug Fix**
* If a player (e.g. a HomePod mini) that was providing the master clock was removed from the set of devices playing, the new master clock retained out-of-date information about the old master clock. This could cause problems going to the next track or to a previous one, causing them not to be heard. Thanks (again!) to [Kristian Dimitrov](https://github.com/Kristian8606) for a precise description of how to cause the problem.

## Version: 1.1-dev-164-g086a123
**Enhancements**
* Improve the accuracy of the clock by including data from the `correctionField` part of a PTP message. Most of the time, this is a fraction of a millisecond, but sometimes it can be larger.
* If a clock timing sample is more than four seconds slow, treat it as the start of a new timing sequence rather than as an error in the current timing sequence.
* Try to restart a clock that stops incrementing towards the start of a timing sequence.

## Version: 1.1-dev-154-g608980e
**Bug Fix**
* Some times, if a PTP clock went to sleep and then woke up, NQPTP would not recognise the new timing data, and, literally, get stuck in the past (!). Getting the problem to manifest itself was difficult -- the clock in the source device (e.g. an iPhone) had to sleep and restart at just the wrong time to cause the problem. Thanks to [Kristian Dimitrov](https://github.com/Kristian8606), [vision4u2](https://github.com/vision4u2) and others.

## Version: 1.1-dev-150-g7af5673
**Bug Fix**
* Remove a noisy debug message that could fill the log. Thanks to [kevocl](https://github.com/kevocl) for the [report](https://github.com/mikebrady/shairport-sync/issues/1481).

## Version: 1.1-dev-142-g15b01c1
**Enhancement**
* Support for FreeBSD

## Version: 1.1-dev-131-g44d4086
***Pesky Change You Can't Ignore***

A change has been made the `nqptp` `systemd` service file, so before updating, please remove the existing service file with the following command:
```
# rm /usr/local/lib/systemd/system/nqptp.service
```
**Bug Fix**
* Remove the invalid `Provides` entry. Thanks to [David Crook](https://github.com/idcrook) for bring this to notice for Shairport Sync. It also applies to NQPTP.

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
