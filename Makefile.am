bin_PROGRAMS = nqptp
nqptp_SOURCES = nqptp.c nqptp-clock-sources.c nqptp-message-handlers.c nqptp-utilities.c general-utilities.c debug.c

AM_CFLAGS = -fno-common -Wno-multichar -Wall -Wextra -Wno-clobbered -Wno-psabi -pthread

install-exec-hook:
	-e /lib/systemd/system || mkdir -p /lib/systemd/system
	-f /lib/systemd/system/nqptp.service || cp nqptp.service /lib/systemd/system