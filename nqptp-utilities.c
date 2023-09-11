/*
 * This file is part of the nqptp distribution (https://github.com/mikebrady/nqptp).
 * Copyright (c) 2021-2022 Mike Brady.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Commercial licensing is also available.
 */

#include "nqptp-utilities.h"
#include "general-utilities.h"
#include <errno.h>
#include <fcntl.h>   // fcntl etc.
#include <ifaddrs.h> // getifaddrs
#include <netinet/in.h>

#ifdef CONFIG_FOR_LINUX
#include <linux/if_packet.h> // sockaddr_ll
#endif

#ifdef CONFIG_FOR_FREEBSD
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <netdb.h>  // getaddrinfo etc.
#include <stdio.h>  // snprintf
#include <stdlib.h> // malloc, free
#include <string.h> // memset strcpy, etc.

#include "debug.h"

void open_sockets_at_port(const char *node, uint16_t port,
                          sockets_open_bundle *sockets_open_stuff) {
  // open up sockets for UDP ports 319 and 320

  // will try IPv6 and IPv4 if IPV6_V6ONLY is not defined

  struct addrinfo hints, *info, *p;
  int ret;

  int sockets_opened = 0;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  char portstr[20];
  snprintf(portstr, 20, "%d", port);

  ret = getaddrinfo(node, portstr, &hints, &info);
  if (ret) {
    die("getifaddrs: %s", gai_strerror(ret));
  }

  for (p = info; p; p = p->ai_next) {
    ret = 0;
    int fd = socket(p->ai_family, p->ai_socktype, IPPROTO_UDP);
    int yes = 1;

    // Handle socket open failures if protocol unavailable (or IPV6 not handled)
    if (fd != -1) {
#ifdef IPV6_V6ONLY
      // some systems don't support v4 access on v6 sockets, but some do.
      // since we need to account for two sockets we might as well
      // always.
      if (p->ai_family == AF_INET6) {
        ret |= setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
      }
#endif

      if (!ret)
        ret = bind(fd, p->ai_addr, p->ai_addrlen);

      int flags = fcntl(fd, F_GETFL);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      // one of the address families will fail on some systems that
      // report its availability. Do not complain.

      if (ret == 0) {
        // debug(1, "socket %d is listening on %s port %d.", fd,
        //       p->ai_family == AF_INET6 ? "IPv6" : "IPv4", port);
        sockets_open_stuff->sockets[sockets_open_stuff->sockets_open].number = fd;
        sockets_open_stuff->sockets[sockets_open_stuff->sockets_open].port = port;
        sockets_open_stuff->sockets[sockets_open_stuff->sockets_open].family = p->ai_family;
        sockets_open_stuff->sockets_open++;
        sockets_opened++;
      }
    }
  }
  freeaddrinfo(info);
  if (sockets_opened == 0) {
    if (port < 1024)
      die("unable to listen on port %d. The error is: \"%s\". NQPTP must run as root to access "
          "this port. Or is another PTP daemon -- possibly another instance on NQPTP -- running "
          "already?",
          port, strerror(errno));
    else
      die("unable to listen on port %d. The error is: \"%s\". "
          "Is another instance on NQPTP running already?",
          port, strerror(errno));
  }
}

void debug_print_buffer(int level, char *buf, size_t buf_len) {
  // printf("Received %u bytes in a packet from %s:%d\n", buf_len, inet_ntoa(si_other.sin_addr),
  // ntohs(si_other.sin_port));
  char *obf =
      malloc(buf_len * 4 + 1); // to be on the safe side -- 4 characters on average for each byte
  if (obf != NULL) {
    char *obfp = obf;
    unsigned int obfc;
    for (obfc = 0; obfc < buf_len; obfc++) {
      snprintf(obfp, 3, "%02X", buf[obfc]);
      obfp += 2;
      if (obfc != buf_len - 1) {
        if (obfc % 32 == 31) {
          snprintf(obfp, 5, " || ");
          obfp += 4;
        } else if (obfc % 16 == 15) {
          snprintf(obfp, 4, " | ");
          obfp += 3;
        } else if (obfc % 4 == 3) {
          snprintf(obfp, 2, " ");
          obfp += 1;
        }
      }
    };
    *obfp = 0;
    switch (buf[0]) {

    case 0x10:
      debug(level, "SYNC: \"%s\".", obf);
      break;
    case 0x18:
      debug(level, "FLUP: \"%s\".", obf);
      break;
    case 0x19:
      debug(level, "DRSP: \"%s\".", obf);
      break;
    case 0x1B:
      debug(level, "ANNC: \"%s\".", obf);
      break;
    case 0x1C:
      debug(level, "SGNL: \"%s\".", obf);
      break;
    default:
      debug(1, "XXXX  \"%s\".", obf); // output this at level 1
      break;
    }
    free(obf);
  }
}

// pass in an array of bytes and a max_length, or a max length of 0 for unlimited
// the actual size will be returned

int get_device_id(uint8_t *id, int *int_length) {
  int max_length = *int_length;
  int response = -1;
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  int i = 0;
  uint8_t *t = id;

  // clear the buffer if non zero length passed in
  for (i = 0; i < max_length; i++) {
    *t++ = 0;
  }

  // look for a useful MAC address
  if (getifaddrs(&ifaddr) != -1) {
    t = id;
    int found = 0;

    for (ifa = ifaddr; ((ifa != NULL) && (found == 0)); ifa = ifa->ifa_next) {
#ifdef AF_PACKET
      if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
        struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
        if ((strcmp(ifa->ifa_name, "lo") != 0)) {
          found = 1;
          if ((max_length == 0) || (s->sll_halen < max_length)) {
            max_length = s->sll_halen;
            *int_length = max_length;
          }
          for (i = 0; i < max_length; i++) {
            *t++ = s->sll_addr[i];
          }
        }
      }
#else
#ifdef AF_LINK
      struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if ((sdl) && (sdl->sdl_family == AF_LINK)) {
        if (sdl->sdl_type == IFT_ETHER) {
          found = 1;
          if ((max_length == 0) || (sdl->sdl_alen < max_length)) {
            max_length = sdl->sdl_alen;
            *int_length = max_length;
          }
          uint8_t *s = (uint8_t *)LLADDR(sdl);
          for (i = 0; i < max_length; i++) {
            *t++ = *s++;
          }
        }
      }
#endif
#endif
    }
    if (found != 0)
      response = 0;
    freeifaddrs(ifaddr);
  }
  return response;
}

uint64_t get_self_clock_id() {
  // make up a clock ID based on an interface's MAC
  int local_clock_id_size = 8; // don't exceed this
  uint8_t local_clock_id[local_clock_id_size];
  memset(local_clock_id, 0, local_clock_id_size);
  if (get_device_id(local_clock_id, &local_clock_id_size) == 0) {
    // if the length of the MAC address is 6 we need to doctor it a little
    // See Section 7.5.2.2.2 IEEE EUI-64 clockIdentity values, NOTE 2

    if (local_clock_id_size == 6) { // i.e. an EUI-48 MAC Address
      local_clock_id[7] = local_clock_id[5];
      local_clock_id[6] = local_clock_id[4];
      local_clock_id[5] = local_clock_id[3];
      local_clock_id[3] = 0xFF;
      local_clock_id[4] = 0xFE;
    }
  }
  // convert to host byte order
  return nctoh64(local_clock_id);
}
