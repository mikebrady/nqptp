## Version: 1.1-dev-51-g812326a
***Pesky Change You Can't Ignore***

A change has been made to where the `nqptp` `systemd` service file is placed. If you are updating from a previous version of `nqptp`, please remove the service file `nqptp.service` from the directory `/lib/systemd/system` (you'll need superuser privileges). A new service file will be installed in the correct location -- `/usr/local/lib/systemd/system` in Ubuntu 20.04 and Raspbian OS (Buster) -- during the `# make install` step.

**Enhancement**
* Further modify `install-exec-hook` to also use the standard `$(libdir)` variable instead of a fixed location. Thanks to [FW](https://github.com/fwcd).

## Version: 1.1-dev-44-g827e624
* Modify `install-exec-hook` to use the standard `$DESTDIR` variable instead of the fixed location `/lib/systemd/`. This is to facilitate build environments that install into a separate directory (e.g. cross-compiling environments). Thanks to [HiFiBerry](https://github.com/hifiberry).

## Version: 1.1-dev-40-g6111d69
* Fix a crashing bug. Thanks to [ste94pz](https://github.com/ste94pz) for reporting and debugging.

## Version: 1.1-dev-36-g880b424
* Initial public version.
