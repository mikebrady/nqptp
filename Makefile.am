bin_PROGRAMS = nqptp
nqptp_SOURCES = nqptp.c nqptp-clock-sources.c nqptp-message-handlers.c nqptp-utilities.c general-utilities.c debug.c

AM_CFLAGS = -fno-common -Wall -Wextra -pthread --include=config.h


if USE_GIT_VERSION
## Check if the git version information has changed and rebuild gitversion.h if so
.PHONY: gitversion-check
gitversion-check: 
	$(top_srcdir)/check-gitversion

BUILT_SOURCES = gitversion-check
CLEANFILES = gitversion-stamp gitversion.h
endif

install-exec-hook:
if BUILD_FOR_LINUX
# Note: 1. NQPTP runs as a dynamic user on systemd-based Linux.
#       2. Access to ports 319 and 320 is given via AmbientCapabilities in the service file.
# If you want to run NQPTP from the command line, e.g. for debugging, run it as root user.
# no installer for System V
if INSTALL_SYSTEMD_STARTUP
	[ -e $(DESTDIR)$(systemdsystemunitdir) ] || mkdir -p $(DESTDIR)$(systemdsystemunitdir)
# don't replace a service file if it already exists...
	[ -e $(DESTDIR)$(systemdsystemunitdir)/nqptp.service ] || cp nqptp.service $(DESTDIR)$(systemdsystemunitdir)
endif
endif

if BUILD_FOR_FREEBSD
# NQPTP runs as root on FreeBSD to access ports 319 and 320
if INSTALL_FREEBSD_STARTUP
	cp nqptp.freebsd /usr/local/etc/rc.d/nqptp
	chmod 555 /usr/local/etc/rc.d/nqptp
endif
endif

if BUILD_FOR_OPENBSD
# NQPTP starts as root on OpenBSD to access ports 319 and 320
# and drops privileges to the user shairport is running as.
endif
