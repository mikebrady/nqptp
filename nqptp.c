/*
 * This file is part of the nqPTP distribution (https://github.com/mikebrady/nqPTP).
 * Copyright (c) 2021 Mike Brady.
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

#include <arpa/inet.h>
#include <stdio.h>  //printf
#include <stdlib.h> //exit(0);
#include <string.h> //memset
#include <sys/socket.h>
#include <unistd.h> // close

#include <ifaddrs.h>
#include <sys/types.h>

#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <inttypes.h>

// References from the IEEE Document ISBN 978-0-7381-5400-8 STD95773.
// "IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and
// Control Systems" The IEEE Std 1588-2008 (Revision of IEEE Std 1588-2002)

// Table 19
enum messageType {
  Sync,
  Delay_Req,
  Pdelay_Req,
  Pdelay_Resp,
  Reserved_4,
  Reserved_5,
  Reserved_6,
  Reserved_7,
  Follow_Up,
  Delay_Resp,
  Pdelay_Resp_Follow_Up,
  Announce,
  Signaling,
  Management,
  Reserved_E,
  Reserved_F
};

struct ptpSource {
  char *ip; // ipv4 or ipv6
  uint64_t t1, t2, t3, t4, t5, previous_offset;
  struct ptpSource *next;
} ptpSource;

#define BUFLEN 4096 // Max length of buffer

#define MAX_OPEN_SOCKETS 32 // up to 32 sockets open on ports 319 and 320

struct socket_info {
  int number;
  uint16_t port;
};

struct socket_info sockets[MAX_OPEN_SOCKETS];

unsigned int sockets_open =
    0; // also doubles as where to put next one, as sockets are never closed.

// struct sockaddr_in6 is bigger than struct sockaddr.
#ifdef AF_INET6
#define SOCKADDR struct sockaddr_storage
#define SAFAMILY ss_family
#else
#define SOCKADDR struct sockaddr
#define SAFAMILY sa_family
#endif

struct sockaddr_in si_me_319, si_me_320, si_other;

uint64_t time_then = 0;

void die(char *s) {
  perror(s);
  exit(1);
}

uint32_t nctohl(const uint8_t *p) { // read 4 characters from *p and do ntohl on them
  // this is to avoid possible aliasing violations
  uint32_t holder;
  memcpy(&holder, p, sizeof(holder));
  return ntohl(holder);
}

uint16_t nctohs(const uint8_t *p) { // read 2 characters from *p and do ntohs on them
  // this is to avoid possible aliasing violations
  uint16_t holder;
  memcpy(&holder, p, sizeof(holder));
  return ntohs(holder);
}

uint64_t timespec_to_ns(struct timespec *tn) {
  uint64_t tnfpsec = tn->tv_sec;
  uint64_t tnfpnsec = tn->tv_nsec;
  tnfpsec = tnfpsec * 1000000000;
  return tnfpsec + tnfpnsec;
}

uint64_t get_time_now() {
  struct timespec tn;
  clock_gettime(CLOCK_MONOTONIC, &tn); // this should be optionally CLOCK_MONOTONIC etc.
  return timespec_to_ns(&tn);
}

struct ptpSource *findOrCreateSource(struct ptpSource **list, char *ip) {
  struct ptpSource *response;
  struct ptpSource **insertion_point = list; // in case the list is empty
  struct ptpSource *crawler = *list;
  if (crawler == NULL) {
    // fprintf(stderr, "No clocks recorded\n");
    insertion_point = list;
  } else {
    while ((crawler->next != NULL) && (strcasecmp(ip, crawler->ip) != 0)) {
      crawler = crawler->next;
    }
    if (strcasecmp(ip, crawler->ip) == 0) {
      // found, so no insertion
      insertion_point = NULL;
    } else {
      // not found, so we are on the last item. Add a new one on to the end.
      insertion_point = &crawler->next;
    }
  }
  // here, if the insertion point is null, then
  // the record is pointer to by crawler
  // otherwise, add a new record at the insertion point
  if (insertion_point == NULL) {
    response = crawler;
  } else {

    response = (struct ptpSource *)malloc(sizeof(ptpSource));
    if (response != NULL) {
      memset((void *)response, 0, sizeof(ptpSource));
      response->ip = strdup(ip);
      *insertion_point = response;
      fprintf(stderr, "Clock record created for \"%s\".\n", ip);
    }
  }
  return response;
}

void print_buffer(char *buf, size_t buf_len) {
  uint64_t time_now = get_time_now();
  if (time_then == 0) {
    printf("          ");
  } else {
    printf("%f  ", (time_now - time_then) * 0.000000001);
  }
  time_then = time_now;
  // printf("Received %u bytes in a packet from %s:%d\n", buf_len, inet_ntoa(si_other.sin_addr),
  // ntohs(si_other.sin_port));
  char obf[BUFLEN * 2 + BUFLEN / 4 + 1 + 1];
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
    printf("SYNC: \"%s\".\n", obf);
    break;
  case 0x18:
    printf("FLUP: \"%s\".\n", obf);
    break;
  case 0x19:
    printf("DRSP: \"%s\".\n", obf);
    break;
  case 0x1B:
    printf("ANNC: \"%s\".\n", obf);
    break;
  case 0x1C:
    printf("SGNL: \"%s\".\n", obf);
    break;
  default:
    printf("      \"%s\".\n", obf);
    break;
  }
}

int main(void) {
  int s319, s320;
  unsigned int slen = sizeof(si_other);
  ssize_t recv_len;

  struct ptpSource *clocks = NULL; // a one-way linked list

  char buf[BUFLEN];

  int status;

  struct __attribute__((__packed__)) ptp_common_message_header {
    uint8_t transportSpecificAndMessageID; // 0x11
    uint8_t reservedAndVersionPTP;         // 0x02
    uint16_t messageLength;
    uint8_t domainNumber;        // 0
    uint8_t reserved_b;          // 0
    uint16_t flags;              // 0x0608
    uint8_t correctionNs[6];     // 0
    uint8_t correctionSubNs[2];  // 0
    uint32_t reserved_l;         // 0
    uint8_t clockIdentity[8];    // MAC
    uint16_t sourcePortID;       // 1
    uint16_t sequenceId;         // increments
    uint8_t controlOtherMessage; // 5
    uint8_t logMessagePeriod;    // 0
  };

  // this is the extra part for a Sync or Delay_Req message
  struct __attribute__((__packed__)) ptp_sync {
    uint8_t originTimestamp[10];
  };

  // this is the extra part for a Sync or Delay_Req message
  struct __attribute__((__packed__)) ptp_delay_req {
    uint8_t originTimestamp[10];
  };

  // this is the extra part for a Follow_Up message
  struct __attribute__((__packed__)) ptp_follow_up {
    uint8_t preciseOriginTimestamp[10];
  };

  // this is the extra part for a Delay_Resp message
  struct __attribute__((__packed__)) ptp_delay_resp {
    uint8_t receiveTimestamp[10];
    uint8_t requestingPortIdentity[10];
  };

  struct __attribute__((__packed__)) ptp_sync_message {
    struct ptp_common_message_header header;
    struct ptp_sync sync;
  };

  struct __attribute__((__packed__)) ptp_delay_req_message {
    struct ptp_common_message_header header;
    struct ptp_delay_req delay_req;
  };

  struct __attribute__((__packed__)) ptp_follow_up_message {
    struct ptp_common_message_header header;
    struct ptp_follow_up follow_up;
  };

  struct __attribute__((__packed__)) ptp_delay_resp_message {
    struct ptp_common_message_header header;
    struct ptp_delay_resp delay_resp;
  };

  struct ptp_delay_req_message m;

  // open up sockets for UDP ports 319 and 320

  struct addrinfo hints, *info, *p;
  int i, ret;

  // replicating nearly the same code for 319 and 320. Ugh!

  // 319...
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  ret = getaddrinfo(NULL, "319", &hints, &info);
  if (ret) {
    fprintf(stderr, "getifaddrs: %s\n", gai_strerror(status));
    die("getaddrinfo");
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

      // one of the address families will fail on some systems that
      // report its availability. do not complain.

      if (ret) {
        fprintf(stderr, "unable to listen on %s port %d. The error is: \"%s\".\n",
                p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 319, strerror(errno));
      } else {
        // fprintf(stderr, "listen on %s port %d.\n", p->ai_family == AF_INET6 ? "IPv6" : "IPv4",
        // 319);
        sockets[sockets_open].number = fd;
        sockets[sockets_open++].port = 319;
      }
    }
  }

  freeaddrinfo(info);

  // 320...
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  ret = getaddrinfo(NULL, "320", &hints, &info);
  if (ret) {
    fprintf(stderr, "getifaddrs: %s\n", gai_strerror(status));
    die("getaddrinfo");
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

      // one of the address families will fail on some systems that
      // report its availability. do not complain.

      if (ret) {
        fprintf(stderr, "unable to listen on %s port %d. The error is: \"%s\".\n",
                p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 320, strerror(errno));
      } else {
        // fprintf(stderr, "listen on %s port %d.\n", p->ai_family == AF_INET6 ? "IPv6" : "IPv4",
        // 320);
        sockets[sockets_open].number = fd;
        sockets[sockets_open++].port = 320;
      }
    }
  }

  freeaddrinfo(info);

  if (sockets_open > 0) {
    while (1) {
      fd_set readSockSet;
      struct timeval timeout;
      FD_ZERO(&readSockSet);
      int smax = -1;
      unsigned int s;
      for (s = 0; s < sockets_open; s++) {
        if (sockets[s].number > smax)
          smax = sockets[s].number;
        FD_SET(sockets[s].number, &readSockSet);
      }

      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      int retval = select(smax + 1, &readSockSet, NULL, NULL, &timeout);
      uint64_t reception_time = get_time_now();

      if (retval > 0) {
        unsigned t;
        for (t = 0; t < sockets_open; t++) {
          if (FD_ISSET(sockets[t].number, &readSockSet)) {
            SOCKADDR from_sock_addr;
            socklen_t from_sock_addr_length = sizeof(SOCKADDR);
            memset(&from_sock_addr, 0, sizeof(SOCKADDR));

            recv_len = recvfrom(sockets[t].number, buf, BUFLEN, 0,
                                (struct sockaddr *)&from_sock_addr, &from_sock_addr_length);

            if (recv_len == -1) {
              die("recvfrom()");
            } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
              // check its credentials
              // the sending and receiving ports must be the same (i.e. 319 -> 319 or 320 -> 320)

              // initialise the connection info
              void *sender_addr = NULL;
              uint16_t sender_port;

              sa_family_t connection_ip_family = from_sock_addr.SAFAMILY;

#ifdef AF_INET6
              if (connection_ip_family == AF_INET6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&from_sock_addr;
                sender_addr = &(sa6->sin6_addr);
                sender_port = ntohs(sa6->sin6_port);
              }
#endif
              if (connection_ip_family == AF_INET) {
                struct sockaddr_in *sa4 = (struct sockaddr_in *)&from_sock_addr;
                sender_addr = &(sa4->sin_addr);
                sender_port = ntohs(sa4->sin_port);
              }
              if (sender_port == sockets[t].port) {
                char sender_string[256];
                memset(sender_string, 0, sizeof(sender_string));
                inet_ntop(connection_ip_family, sender_addr, sender_string, sizeof(sender_string));

                //fprintf(stderr, "connection from %s:%u on port %u\n", sender_string, sender_port,
                //        sockets[t].port);

                // print_buffer(buf, recv_len);

                // now, find or create a record for this ip
                struct ptpSource *the_clock = findOrCreateSource(&clocks, sender_string);
                switch (buf[0] & 0xF) {
                case Sync: { // if it's a sync
                  struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
                  the_clock->t2 = reception_time;
                  memset(&m, 0, sizeof(m));
                  m.header.transportSpecificAndMessageID = 0x11;
                  m.header.reservedAndVersionPTP = 0x02;
                  m.header.messageLength = htons(44);
                  m.header.flags = htons(0x608);
                  m.header.sourcePortID = htons(1);
                  m.header.controlOtherMessage = 5;
                  m.header.sequenceId = msg->header.sequenceId;
                  struct ifaddrs *ifaddr = NULL;
                  struct ifaddrs *ifa = NULL;

                  if ((status = getifaddrs(&ifaddr) == -1)) {
                    fprintf(stderr, "getifaddrs: %s\n", gai_strerror(status));
                  } else {
                    int found = 0;
                    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                      if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
                        struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                        if ((strcmp(ifa->ifa_name, "lo") != 0) && (found == 0)) {
                          memcpy(&m.header.clockIdentity, &s->sll_addr, s->sll_halen);
                          found = 1;
                        }
                      }
                    }
                    freeifaddrs(ifaddr);
                  }
                	fprintf(stderr, "DREQ to %s\n", the_clock->ip);
                  the_clock->t3 = get_time_now();
                  if (sendto(sockets[t].number, &m, sizeof(m), 0, (const struct sockaddr *)&from_sock_addr, from_sock_addr_length) ==
                      -1) {
                    fprintf(stderr, "sendto: %s\n", strerror(errno));
                    return 4;
                  }
                } break;

                case Follow_Up: {
                  struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
                  uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
                  uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
                  uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
                  uint64_t preciseOriginTimestamp = seconds_hi;
                  preciseOriginTimestamp = preciseOriginTimestamp << 32;
                  preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
                  preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
                  preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;
                  the_clock->t1 = preciseOriginTimestamp;
                } break;
                case Delay_Resp: {
                  struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;
                  uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
                  uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
                  uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
                  uint64_t receiveTimestamp = seconds_hi;
                  receiveTimestamp = receiveTimestamp << 32;
                  receiveTimestamp = receiveTimestamp + seconds_low;
                  receiveTimestamp = receiveTimestamp * 1000000000L;
                  receiveTimestamp = receiveTimestamp + nanoseconds;
                  the_clock->t4 = receiveTimestamp;
                  the_clock->t5 = reception_time; // t5 - t3 gives us the out-and-back time locally -- an
                                       // instantaneous quality index

                  // calculate delay and calculate offset
                  // fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ", t4: %"
                  // PRIx64
                  // ".\n",t1,t2,t3,t4); fprintf(stderr, "nominal remote transaction time: %" PRIx64
                  // " =
                  // %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n", t4-t1,
                  // t4-t1, t3-t2, t3-t2);
                  uint64_t offset = the_clock->t1 - the_clock->t2;
                  if (the_clock->previous_offset == 0)
                    fprintf(stderr, "offset: %" PRIx64 ".\n", offset);
                  else {
                    int64_t variation = offset - the_clock->previous_offset;
                    fprintf(stderr,
                            "%s: remote transaction time: %f, offset: %" PRIx64
                            ", variation: %f, turnaround: %f \n", the_clock->ip,
                            (the_clock->t4 - the_clock->t1) * 0.000000001, offset, variation * 0.000000001,
                            (the_clock->t5 - the_clock->t2) * 0.000000001);
                  }
                  the_clock->previous_offset = offset;
                  // fprintf(stderr, "Offset: %" PRIx64 ", delay %f.\n", offset, delay*0.000000001);

                } break;
                default:
                  break;
                }

              } else {
                fprintf(stderr, "Packet dropped because ports don't match.\n");
              }
            }
          }
        }

/*
        if (FD_ISSET(s319, &readSockSet)) {
          // printf("S319 Client query incoming...\n");
          // try to receive some data, this is a blocking call
          if ((recv_len = recvfrom(s319, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen)) ==
              -1) {
            die("recvfrom() 319");
          } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
            // find or create a ptpSource record for this one.
            // struct ptpSource *the_clock = findOrCreateSource(&clocks);
            // print_buffer(buf, recv_len);
            switch (buf[0] & 0xF) {
            case Sync: { // if it's a sync
              struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
              t2 = reception_time;
              memset(&m, 0, sizeof(m));
              m.header.transportSpecificAndMessageID = 0x11;
              m.header.reservedAndVersionPTP = 0x02;
              m.header.messageLength = htons(44);
              m.header.flags = htons(0x608);
              m.header.sourcePortID = htons(1);
              m.header.controlOtherMessage = 5;
              m.header.sequenceId = msg->header.sequenceId;
              struct ifaddrs *ifaddr = NULL;
              struct ifaddrs *ifa = NULL;

              if ((status = getifaddrs(&ifaddr) == -1)) {
                fprintf(stderr, "getifaddrs: %s\n", gai_strerror(status));
              } else {
                int found = 0;
                for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                  if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
                    struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                    if ((strcmp(ifa->ifa_name, "lo") != 0) && (found == 0)) {
                      memcpy(&m.header.clockIdentity, &s->sll_addr, s->sll_halen);
                      found = 1;
                    }
                  }
                }
                freeifaddrs(ifaddr);
              }
              t3 = get_time_now();
              if (sendto(s319, &m, sizeof(m), 0, (const struct sockaddr *)&si_other, slen) == -1) {
                fprintf(stderr, "sendto: %s\n", strerror(errno));
                return 4;
              }
            } break;
            default:
              break;
            }
          }
        }

        if (FD_ISSET(s320, &readSockSet)) {
          // printf("S320 Client query incoming...\n");
          // try to receive some data, this is a blocking call
          if ((recv_len = recvfrom(s320, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen)) ==
              -1) {
            die("recvfrom() 320");

          } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
            // print_buffer(buf, recv_len);
            switch (buf[0] & 0xF) {
            case Follow_Up: {
              struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
              uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
              uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
              uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
              uint64_t preciseOriginTimestamp = seconds_hi;
              preciseOriginTimestamp = preciseOriginTimestamp << 32;
              preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
              preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
              preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;
              t1 = preciseOriginTimestamp;
            } break;
            case Delay_Resp: {
              struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;
              uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
              uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
              uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
              uint64_t receiveTimestamp = seconds_hi;
              receiveTimestamp = receiveTimestamp << 32;
              receiveTimestamp = receiveTimestamp + seconds_low;
              receiveTimestamp = receiveTimestamp * 1000000000L;
              receiveTimestamp = receiveTimestamp + nanoseconds;
              t4 = receiveTimestamp;
              t5 = reception_time; // t5 - t3 gives us the out-and-back time locally -- an
                                   // instantaneous quality index

              // calculate delay and calculate offset
              // fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ", t4: %"
              // PRIx64
              // ".\n",t1,t2,t3,t4); fprintf(stderr, "nominal remote transaction time: %" PRIx64 " =
              // %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n", t4-t1,
              // t4-t1, t3-t2, t3-t2);
              uint64_t offset = t1 - t2;
              if (previous_offset == 0)
                fprintf(stderr, "offset: %" PRIx64 ".\n", offset);
              else {
                int64_t variation = offset - previous_offset;
                fprintf(stderr,
                        "remote transaction time: %f, offset: %" PRIx64
                        ", variation: %f, turnaround: %f \n",
                        (t4 - t1) * 0.000000001, offset, variation * 0.000000001,
                        (t5 - t2) * 0.000000001);
              }
              previous_offset = offset;
              // fprintf(stderr, "Offset: %" PRIx64 ", delay %f.\n", offset, delay*0.000000001);

            } break;

            default:
              // fprintf(stderr, "320 other\n");
              break;
            }
          }
        }
*/
      } else if (retval < 0) {
        // check errno/WSAGetLastError(), call perror(), etc ...
      }
    }
  }

  // here, close all the sockets...

  return 0;
}