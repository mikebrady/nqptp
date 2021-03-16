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
#include <sys/ioctl.h>

#include <inttypes.h>

// References from the IEEE Document ISBN 978-0-7381-5400-8 STD95773.
// "IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and
// Control Systems" The IEEE Std 1588-2008 (Revision of IEEE Std 1588-2002)

// transaction tracking
enum stage {
  nothing_seen,
  sync_seen,
  follow_up_seen,
  waiting_for_sync // this when you are waiting out a sync for a new cycle
};

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

#define MAX_TIMING_SAMPLES 1
struct timing_samples {
  uint64_t local, remote;
} timing_samples;

struct ptpSource {
  char *ip;               // ipv4 or ipv6
  int discarding_packets; // true if discarding packets for a period
  uint64_t discard_until_time;
  uint16_t sequence_number;
  enum stage current_stage;
  uint64_t t1, t2, t3, t4, t5, previous_offset;
  struct timing_samples samples[MAX_TIMING_SAMPLES];
  int vacant_samples; // the number of elements in the timing_samples array that are not yet used
  int next_sample_goes_here;
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
  clock_gettime(CLOCK_REALTIME, &tn); // this should be optionally CLOCK_MONOTONIC etc.
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
      response->vacant_samples = MAX_TIMING_SAMPLES; // no valid samples yet
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
  int ret;

  // replicating nearly the same code for 319 and 320. Ugh!

  // 319...
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  ret = getaddrinfo(NULL, "319", &hints, &info);
  if (ret) {
    fprintf(stderr, "getifaddrs: %s\n", gai_strerror(ret));
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

      if (ret == 0)
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &yes, sizeof(yes));
      if (ret != 0)
        fprintf(stderr, "unable to enable timestamping.\n");

      int val;
      socklen_t len = sizeof(val);
      if (getsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &val, &len) < 0)
        printf("%s: %s\n", "getsockopt SO_TIMESTAMPNS", strerror(errno));
      else
        printf("SO_TIMESTAMPNS %d\n", val);

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
    fprintf(stderr, "getifaddrs: %s\n", gai_strerror(ret));
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

      if (ret == 0)
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &yes, sizeof(yes));
      if (ret != 0)
        fprintf(stderr, "unable to enable timestamping.\n");

      int val;
      socklen_t len = sizeof(val);
      if (getsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &val, &len) < 0)
        printf("%s: %s\n", "getsockopt SO_TIMESTAMPNS", strerror(errno));
      else
        printf("SO_TIMESTAMPNS %d\n", val);

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
      uint64_t discard_interval = 50000000; // 50 ms.
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

      if (retval > 0) {
        unsigned t;
        for (t = 0; t < sockets_open; t++) {
          if (FD_ISSET(sockets[t].number, &readSockSet)) {

            SOCKADDR from_sock_addr;
            socklen_t from_sock_addr_length = sizeof(SOCKADDR);
            memset(&from_sock_addr, 0, sizeof(SOCKADDR));

            struct {
              struct cmsghdr cm;
              char control[512];
            } control;

            struct msghdr msg;
            struct iovec iov[1];
            memset(iov, 0, sizeof(iov));
            memset(&msg, 0, sizeof(msg));
            memset(&control, 0, sizeof(control));

            iov[0].iov_base = buf;
            iov[0].iov_len = BUFLEN;

            msg.msg_iov = iov;
            msg.msg_iovlen = 1;

            msg.msg_name = &from_sock_addr;
            msg.msg_namelen = sizeof(from_sock_addr);
            msg.msg_control = &control;
            msg.msg_controllen = sizeof(control);

            // int msgsize = recv(udpsocket_fd, &msg_buffer, 4, 0);

            recv_len = recvmsg(sockets[t].number, &msg, 0);

            // clang-format off
/*
            SOCKADDR from_sock_addr;
            socklen_t from_sock_addr_length = sizeof(SOCKADDR);
            memset(&from_sock_addr, 0, sizeof(SOCKADDR));

            recv_len = recvfrom(sockets[t].number, buf, BUFLEN, 0,
                                (struct sockaddr *)&from_sock_addr, &from_sock_addr_length);
*/
            // clang-format on

            if (recv_len == -1) {
              die("recvfrom()");
            } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
              uint64_t reception_time = 0;

              // fprintf(stderr, "Received %d bytes control message.\n", msg.msg_controllen);

              // get the time
              int level, type;
              struct cmsghdr *cm;
              struct timespec *ts = NULL;
              for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
                level = cm->cmsg_level;
                type = cm->cmsg_type;
                if (SOL_SOCKET == level && SO_TIMESTAMPNS == type) {
                  ts = (struct timespec *)CMSG_DATA(cm);
                  reception_time = ts->tv_sec;
                  reception_time = reception_time * 1000000000;
                  reception_time = reception_time + ts->tv_nsec;
                }
              }

              // check its credentials
              // the sending and receiving ports must be the same (i.e. 319 -> 319 or 320 -> 320)

              // initialise the connection info
              void *sender_addr = NULL;
              uint16_t sender_port = 0;

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

                // fprintf(stderr, "connection from %s:%u on port %u\n", sender_string,
                // sender_port,
                //        sockets[t].port);

                // print_buffer(buf, recv_len);

                // now, find or create a record for this ip
                struct ptpSource *the_clock = findOrCreateSource(&clocks, sender_string);
                if (the_clock->discarding_packets != 0) {
                  int64_t discard_time_remaining = the_clock->discard_until_time - reception_time;
                  if (discard_time_remaining <= 0)
                    the_clock->discarding_packets = 0;
                }

                if (the_clock->discarding_packets == 0) {
                  switch (buf[0] & 0xF) {
                  case Sync: { // if it's a sync
                    struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
                    if ((the_clock->current_stage != nothing_seen) &&
                        (the_clock->current_stage != waiting_for_sync)) {

                      fprintf(stderr,
                              "Sync expecting to be in state nothing_seen (%u) or waiting_for_sync "
                              "(%u). Stage error -- "
                              "current state is %u. Discarding. %s\n",
                              nothing_seen, waiting_for_sync, the_clock->current_stage,
                              the_clock->ip);

                      the_clock->current_stage = waiting_for_sync;
                      // the_clock->discarding_packets = 1;
                      the_clock->discard_until_time = reception_time + discard_interval;
                    }
                    the_clock->sequence_number = ntohs(msg->header.sequenceId);
                    the_clock->t2 = reception_time;
                    memset(&m, 0, sizeof(m));
                    m.header.transportSpecificAndMessageID = 0x11;
                    m.header.reservedAndVersionPTP = 0x02;
                    m.header.messageLength = htons(44);
                    m.header.flags = htons(0x608);
                    m.header.sourcePortID = htons(1);
                    m.header.controlOtherMessage = 5;
                    m.header.sequenceId = htons(the_clock->sequence_number);
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

                    // fprintf(stderr, "DREQ to %s\n", the_clock->ip);
                    if (sendto(sockets[t].number, &m, sizeof(m), 0,
                               (const struct sockaddr *)&from_sock_addr,
                               from_sock_addr_length) == -1) {
                      fprintf(stderr, "sendto: %s\n", strerror(errno));
                      return 4;
                    }

                    struct timeval tv_ioctl;
                    tv_ioctl.tv_sec = 0;
                    tv_ioctl.tv_usec = 0;
                    int error = ioctl(sockets[t].number, SIOCGSTAMP, &tv_ioctl);
                    uint64_t transmission_time = tv_ioctl.tv_sec;
                    transmission_time = transmission_time * 1000000;
                    transmission_time = transmission_time + tv_ioctl.tv_usec;
                    transmission_time = transmission_time * 1000;
                    the_clock->t3 = transmission_time;
                    // int64_t ttd = transmission_time - the_clock->t3;
                    // fprintf(stderr, "transmission time delta: %f.\n", ttd*0.000000001);

                    the_clock->current_stage = sync_seen;
                  } break;

                  case Follow_Up: {
                    struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
                    if ((the_clock->current_stage == sync_seen) &&
                        (the_clock->sequence_number == ntohs(msg->header.sequenceId))) {
                      uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
                      uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
                      uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
                      uint64_t preciseOriginTimestamp = seconds_hi;
                      preciseOriginTimestamp = preciseOriginTimestamp << 32;
                      preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
                      preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
                      preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;
                      the_clock->t1 = preciseOriginTimestamp;
                      the_clock->current_stage = follow_up_seen;
                    } else {
                      if (the_clock->current_stage != waiting_for_sync) {

                        fprintf(stderr,
                                "Follow_Up expecting to be in state sync_seen (%u). Stage error -- "
                                "current state is %u. Discarding. %s\n",
                                sync_seen, the_clock->current_stage, the_clock->ip);

                        the_clock->current_stage = waiting_for_sync;
                        // the_clock->discarding_packets = 1;
                        the_clock->discard_until_time = reception_time + discard_interval;
                      }
                    }
                  } break;
                  case Delay_Resp: {
                    struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;
                    if ((the_clock->current_stage == follow_up_seen) &&
                        (the_clock->sequence_number == ntohs(msg->header.sequenceId))) {
                      uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
                      uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
                      uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
                      uint64_t receiveTimestamp = seconds_hi;
                      receiveTimestamp = receiveTimestamp << 32;
                      receiveTimestamp = receiveTimestamp + seconds_low;
                      receiveTimestamp = receiveTimestamp * 1000000000L;
                      receiveTimestamp = receiveTimestamp + nanoseconds;
                      the_clock->t4 = receiveTimestamp;
                      the_clock->t5 =
                          reception_time; // t5 - t3 gives us the out-and-back time locally
                                          // -- an instantaneous quality index
                                          // t5 - t2 gives us an overall interchange time
                                          // from the Sync to the Delay Resp

                      if ((the_clock->t5 - the_clock->t2) < 15 * 1000000) {
                        if ((the_clock->t4 - the_clock->t1) < 60 * 1000000) {

                          // calculate delay and calculate offset
                          // fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ",
                          // t4:
                          // %" PRIx64
                          // ".\n",t1,t2,t3,t4); fprintf(stderr, "nominal remote transaction time:
                          // %" PRIx64 " =
                          // %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n",
                          // t4-t1, t4-t1, t3-t2, t3-t2);

                          // now, store the remote and local times in the array
                          the_clock->samples[the_clock->next_sample_goes_here].local =
                              the_clock->t2;
                          the_clock->samples[the_clock->next_sample_goes_here].remote =
                              the_clock->t1;
                          the_clock->next_sample_goes_here++;
                          if (the_clock->next_sample_goes_here == MAX_TIMING_SAMPLES)
                            the_clock->next_sample_goes_here = 0;
                          if (the_clock->vacant_samples > 0)
                            the_clock->vacant_samples--;

                          // fprintf(stderr, "Offset: %" PRIx64 ", delay %f.\n", offset,
                          // delay*0.000000001);

                          // clang-format off

 											  /*

                        // here, let's try to use the t1 - remote time and t2 - local time
                        // records to estimate the relationship between the local clock (x) and
                        // remote clock(y) estimate a figure for drift between the local
                        // clock (x) and the remote clock (y)

                        // if we plug in a local interval, we will get back what that is in remote
                        // time

                        // calculate the line of best fit for relating the local time and the remote
                        // time we will calculate the slope, which is the drift. See
                        // https://www.varsitytutors.com/hotmath/hotmath_help/topics/line-of-best-fit

                        long double y_bar = 0; // remote timestamp average
                        long double x_bar = 0; // local timestamp average
                        int sample_count = 0;
                        long double gradient;
                        long double intercept;
                        int i;
                        for (i = 0; i < MAX_TIMING_SAMPLES - the_clock->vacant_samples; i++) {
                          y_bar += (1.0 * the_clock->samples[i].remote);
                          x_bar += (1.0 * the_clock->samples[i].local);
                          sample_count++;
                        }

                        y_bar = y_bar / sample_count;
                        x_bar = x_bar / sample_count;

                        long double xid, yid;
                        long double mtl, mbl;
                        mtl = 0;
                        mbl = 0;
                        for (i = 0; i < MAX_TIMING_SAMPLES - the_clock->vacant_samples; i++) {
                          xid = 1.0 * the_clock->samples[i].local - x_bar;
                          yid = 1.0 * the_clock->samples[i].remote - y_bar;
                          mtl = mtl + xid * yid;
                          mbl = mbl + xid * xid;
                        }

                        if (mbl)
                          gradient = (1.0 * mtl) / mbl;
                        else {
                          gradient = 1.0;
                        }

                        // intercept = y_bar  - gradient * x_bar

                        intercept = 1.0 * y_bar - gradient * x_bar;

                        // y = mx + c
                        // remote = gradient * local + intercept

                        long double remote_f = gradient * the_clock->t2 + intercept;
                        uint64_t remote_estimate = (uint64_t)remote_f;
                        // fprintf(stderr, "remote actual: %" PRIx64 ", remote estimated: %" PRIx64
                        // ".\n", the_clock->t1, remote_estimate);

                        // uint64_t offset = the_clock->t1 - the_clock->t2;
                        uint64_t offset = remote_estimate - the_clock->t2;
                       */

                          // clang-format on

                          // here, calculate the average offset

                          int e;
                          long double offsets = 0;
                          for (e = 0; e < MAX_TIMING_SAMPLES - the_clock->vacant_samples; e++) {
                            offsets = offsets + 1.0 * (the_clock->samples[e].remote -
                                                       the_clock->samples[e].local);
                          }

                          offsets = offsets / (MAX_TIMING_SAMPLES - the_clock->vacant_samples);

                          uint64_t offset = (uint64_t)offsets;
                          long double gradient = 1.0;
                          // uint64_t offset = the_clock->t1 - the_clock->t2;

                          if (the_clock->previous_offset == 0)
                            fprintf(stderr, "offset: %" PRIx64 ".\n", offset);
                          else {
                            int64_t variation = offset - the_clock->previous_offset;
                            fprintf(stderr,
                                    "remote transaction time: %f, offset: %" PRIx64
                                    ", variation: %+f, turnaround: %f delta (ppm): %+Lf ip: %s.\n",
                                    (the_clock->t4 - the_clock->t1) * 0.000000001, offset,
                                    variation * 0.000000001,
                                    (the_clock->t5 - the_clock->t2) * 0.000000001,
                                    (gradient - 1.0) * 1000000, the_clock->ip);
                          }
                          the_clock->previous_offset = offset;
                        } else {
                          fprintf(stderr,
                                  "t4 - t1 (sync and delay response) time is too long. Discarding. "
                                  "%s\n",
                                  the_clock->ip);
                        }
                      } else {
                        fprintf(stderr, "t5 - t2 time (cycle time) is too long. Discarding. %s\n",
                                the_clock->ip);
                      }
                      the_clock->current_stage = nothing_seen;
                    } else {
                      if (the_clock->current_stage != waiting_for_sync) {

                        fprintf(
                            stderr,
                            "Delay_Resp expecting to be in state sync_seen (%u). Stage error -- "
                            "current state is %u. Discarding. %s\n",
                            sync_seen, the_clock->current_stage, the_clock->ip);

                        the_clock->current_stage = waiting_for_sync;
                        // the_clock->discarding_packets = 1;
                        the_clock->discard_until_time = reception_time + discard_interval;
                      }
                    }
                  } break;
                  default:
                    break;
                  }
                }
              }
            }
          }
        }

      } else if (retval < 0) {
        // check errno/WSAGetLastError(), call perror(), etc ...
      }
    }
  }

  // here, close all the sockets...

  return 0;
}