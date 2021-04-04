bin_PROGRAMS = nqptp
nqptp_SOURCES = nqptp.c nqptp-clock-sources.c nqptp-utilities.c general-utilities.c debug.c

AM_CFLAGS = -fno-common -Wno-multichar -Wall -Wextra -Wno-clobbered -Wno-psabi -pthread

install-exec-hook:
	getent group nqptp &>/dev/null || groupadd -r nqptp >/dev/null
	[ -e /lib/systemd/system ] || mkdir -p /lib/systemd/system
	[ -f /lib/systemd/system/nqptp.service ] || cp nqptp.service /lib/systemd/system
