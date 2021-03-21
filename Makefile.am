bin_PROGRAMS = nqptp
nqptp_SOURCES = nqptp.c

AM_CFLAGS = -fno-common -Wno-multichar -Wall -Wextra -Wno-clobbered -Wno-psabi -pthread

install-exec-hook:
	getent group nqptp &>/dev/null || groupadd -r nqptp >/dev/null
	[ -e $(DESTDIR)$(systemdsystemunitdir) ] || mkdir -p $(DESTDIR)$(systemdsystemunitdir)
	[ -f $(DESTDIR)$(systemdsystemunitdir)/nqptp.service ] || cp nqptp.service $(DESTDIR)$(systemdsystemunitdir)
endif
