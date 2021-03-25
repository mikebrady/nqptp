/*
 * This file is part of the nqptp distribution (https://github.com/mikebrady/nqptp).
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

// 0 means no debug messages. 3 means lots!

#define DEBUG_LEVEL 0

#include "debug.h"
#include "nqptp-shm-structures.h"

#include <arpa/inet.h>
#include <stdio.h>  //printf
#include <stdlib.h> //malloc;
#include <string.h> //memset
#include <sys/socket.h>
#include <unistd.h> // close

#include <ifaddrs.h>
#include <pthread.h>
#include <sys/types.h>

#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>

#include <inttypes.h>

#include <asm/types.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include <fcntl.h> /* For O_* constants */
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */

#include <grp.h>

#include <signal.h>
#include <sys/epoll.h>

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif
#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS 35
#endif
#ifndef SIOCGSTAMPNS
#define SIOCGSTAMPNS 0x8907
#endif
#ifndef SIOCSHWTSTAMP
#define SIOCSHWTSTAMP 0x89b0
#endif

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

// 8 samples per second

#define MAX_TIMING_SAMPLES 480
struct timing_samples {
  uint64_t local, remote, local_to_remote_offset;
} timing_samples;

struct ptpSource {
  char ip[64]; // ipv4 or ipv6
  uint64_t clock_id;
  uint16_t sequence_number;
  enum stage current_stage;
  uint64_t t1, t2, t3, t4, t5, previous_offset, previous_estimated_offset;
  int at_least_one_follow_up_seen, at_least_one_delay_resp_seen;
  struct timing_samples samples[MAX_TIMING_SAMPLES];
  int vacant_samples; // the number of elements in the timing_samples array that are not yet used
  int next_sample_goes_here; // point to where in the timing samples array the next entries should
                             // go
  int shared_clock_number;   // which entry to use in the shared memory, could be -1!
  uint64_t sample_number;    // should roll over in 2^61 seconds!
  int in_use;
} ptpSource;

#define BUFLEN 4096 // Max length of buffer

#define MAX_OPEN_SOCKETS 32 // up to 32 sockets open on ports 319 and 320

struct socket_info {
  int number;
  uint16_t port;
};
struct ptpSource sources[MAX_SHARED_CLOCKS];
struct socket_info sockets[MAX_OPEN_SOCKETS];
unsigned int sockets_open =
    0; // also doubles as where to put next one, as sockets are never closed.
struct shm_structure *shared_memory = NULL;
struct ptpSource *clocks = NULL; // a one-way linked list
int epoll_fd;

int t4_t1_difference_reported = 0;

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

struct ptpSource *find_source(char *sender_string, uint64_t packet_clock_id) {
  struct ptpSource *response = NULL;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_SHARED_CLOCKS)) {
    if ((sources[i].in_use != 0) && (sources[i].clock_id == packet_clock_id) &&
        (strcasecmp(sender_string, (const char *)&sources[i].ip) == 0))
      found = 1;
    else
      i++;
  }
  if (found != 0)
    response = &sources[i];
  return response;
}

struct ptpSource *create_source(char *sender_string, uint64_t packet_clock_id) {
  struct ptpSource *response = NULL;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_SHARED_CLOCKS)) {
    if (sources[i].in_use == 0)
      found = 1;
    else
      i++;
  }
  if (found != 0) {
    memset(&sources[i], 0, sizeof(struct ptpSource));
    sources[i].in_use = 1;
    strncpy((char *)&sources[i].ip, sender_string, sizeof(ptpSource.ip) - 1);
    sources[i].clock_id = packet_clock_id;
    sources[i].t1 = 0;
    sources[i].t2 = 0;
    sources[i].t3 = 0;
    sources[i].t4 = 0;
    sources[i].at_least_one_follow_up_seen = 0;
    sources[i].at_least_one_delay_resp_seen = 0;
    sources[i].current_stage = nothing_seen;
    sources[i].shared_clock_number = -1;
    response = &sources[i];
    debug(1, "activated source %d with clock_id %" PRIx64 " on ip: %s.", i, sources[i].clock_id,
          &sources[i].ip);
  } else {
    die("Clock table full!");
  }
  return response;
}

void deactivate_old_sources(uint64_t reception_time) {
  debug(3, "deactivate_old_sources");
  int i;
  for (i = 0; i < MAX_SHARED_CLOCKS; i++) {
    if (sources[i].in_use != 0) {
      int64_t time_since_last_sync = reception_time - sources[i].t2;
      if (time_since_last_sync > 1000000000) {
        if (sources[i].shared_clock_number != -1) {
          shared_memory->clocks[sources[i].shared_clock_number].valid = 0;
          debug(1, "deactivated shared clock %d with clock_id %" PRIx64 " on ip: %s.",
                sources[i].shared_clock_number,
                shared_memory->clocks[sources[i].shared_clock_number].clock_id,
                &shared_memory->clocks[sources[i].shared_clock_number].ip);
        }
        sources[i].in_use = 0;
        sources[i].shared_clock_number = -1;
        debug(1, "deactivated source %d with clock_id %" PRIx64 " on ip: %s.", i,
              sources[i].clock_id, &sources[i].ip);
      }
    }
  }
}

void update_clock_interface(struct ptpSource *the_clock) {
  // we may have a Delay_Resp or we may only have a Follow_Up,
  // but we have to make the best of it.

  // we get
  // t1 from Follow_Up -- when Sync was sent
  // t2 from Sync -- when Sync was received
  // t3 from Sync -- when Delay_Req was sent
  // t4 from Delay_Resp -- when Delay_Resp was sent which could be equal to t1.

  // (t4 - t1) [always positive, a difference of two distant clock times]
  // less (t3 -t2) [always positive, a difference of two local clock times]
  // is equal to t(m->s) + t(s->m), thus twice the propagation time
  // assuming symmetrical delays.

  // sometimes, t4 and t1 are the same

  // calculate delay and calculate offset
  // fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ",
  // t4:
  // %" PRIx64
  // ".\n",t1,t2,t3,t4); fprintf(stderr, "nominal remote transaction time:
  // %" PRIx64 " =
  // %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n",
  // t4-t1, t4-t1, t3-t2, t3-t2);

  // we definitely have t2 and t1
  uint64_t instantaneous_offset = the_clock->t1 - the_clock->t2;
  int64_t change_in_offset = instantaneous_offset - the_clock->previous_offset;

  // now, decide whether to keep the sample for averaging, etc.
  the_clock->sample_number++;
  if (the_clock->sample_number == 16) {             // discard the approx first two seconds!
                                                    // remove previous samples before this number
    the_clock->vacant_samples = MAX_TIMING_SAMPLES; // invalidate all the previous samples used for
                                                    // averaging, etc.
    the_clock->next_sample_goes_here = 0;
  }

  int64_t discontinuity_threshold = 250000000; // nanoseconds
  if ((change_in_offset > discontinuity_threshold) ||
      (change_in_offset < (-discontinuity_threshold))) {

    debug(3, "large discontinuity of %+f seconds detected, sequence %u.",
          change_in_offset * 0.000000001, the_clock->sequence_number);
    the_clock->vacant_samples = MAX_TIMING_SAMPLES; // invalidate all the previous samples used for
                                                    // averaging, etc.
    the_clock->next_sample_goes_here = 0;
  }

  // now, store the remote and local times in the array
  the_clock->samples[the_clock->next_sample_goes_here].local = the_clock->t2;
  the_clock->samples[the_clock->next_sample_goes_here].remote = the_clock->t1;
  uint64_t diff = the_clock->t1 - the_clock->t2;
  the_clock->samples[the_clock->next_sample_goes_here].local_to_remote_offset = diff;
  the_clock->next_sample_goes_here++;
  if (the_clock->next_sample_goes_here == MAX_TIMING_SAMPLES)
    the_clock->next_sample_goes_here = 0;
  if (the_clock->vacant_samples > 0)
    the_clock->vacant_samples--;

  uint64_t estimated_offset = instantaneous_offset;

  // here, calculate the average offset

  int e;
  long double offsets = 0;
  int sample_count = MAX_TIMING_SAMPLES - the_clock->vacant_samples;
  for (e = 0; e < sample_count; e++) {
    uint64_t ho = the_clock->samples[e].local_to_remote_offset;
    ho = ho >> 12;

    offsets = offsets + 1.0 * ho;
  }

  offsets = offsets / sample_count;

  // uint64_t offset = (uint64_t)offsets;

  estimated_offset = (uint64_t)offsets;

  estimated_offset = estimated_offset << 12;

  int64_t variation = 0;

  if (the_clock->previous_estimated_offset != 0) {
    variation = estimated_offset - the_clock->previous_estimated_offset;
  } else {
    estimated_offset = instantaneous_offset;
  }

  // here, update the shared clock information

  int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
  if (rc != 0)
    warn("Can't acquire mutex to update a clock!");

  // if necessary, initialise a new shared clock record
  // hacky.

  if (the_clock->shared_clock_number == -1) {

    // associate and initialise a shared clock record
    int i = 0;
    while ((shared_memory->clocks[i].valid != 0) && (i < MAX_SHARED_CLOCKS)) {
      i++;
    }
    if (i == MAX_SHARED_CLOCKS)
      die("All %d clock entries are in use -- no more available!", MAX_SHARED_CLOCKS);
    the_clock->shared_clock_number = i;

    strncpy((char *)&shared_memory->clocks[i].ip, (const char *)&the_clock->ip,
            INET6_ADDRSTRLEN - 1);
    shared_memory->clocks[i].clock_id = the_clock->clock_id;
    shared_memory->clocks[i].valid = 1;
    shared_memory->clocks[i].reserved = 0;
    shared_memory->clocks[i].flags = 0;
    debug(1,
          "shared memory clock entry %d created for Clock ID: '%" PRIx64
          "' at %s. The entry reads: '%" PRIx64 "', %s.",
          i, the_clock->clock_id, the_clock->ip, shared_memory->clocks[i].clock_id,
          &shared_memory->clocks[i].ip);
  }

  // now update the clock
  shared_memory->clocks[the_clock->shared_clock_number].local_time = the_clock->t2;
  shared_memory->clocks[the_clock->shared_clock_number].local_to_source_time_offset =
      estimated_offset;

  rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
  if (rc != 0)
    warn("Can't release mutex after updating a clock!");

  debug(3,
        "id: %20" PRIu64 ", time: 0x%" PRIx64 ", offset: %" PRIx64
        ", variation: %+f, turnaround: %f, ip: %s, sequence: %u samples: %d.",
        the_clock->clock_id, the_clock->t2 + estimated_offset, estimated_offset,
        variation * 0.000000001, (the_clock->t5 - the_clock->t2) * 0.000000001, the_clock->ip,
        the_clock->sequence_number, sample_count);

  the_clock->previous_estimated_offset = estimated_offset;
  the_clock->previous_offset = instantaneous_offset;
}

void debug_print_buffer(int level, char *buf, size_t buf_len) {
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
    debug(level, "      \"%s\".", obf);
    break;
  }
}

void goodbye(void) {
  // close any open sockets
  unsigned int i;
  for (i = 0; i < sockets_open; i++)
    close(sockets[i].number);
  if (shared_memory != NULL) {
    // mmap cleanup
    if (munmap(shared_memory, sizeof(struct shm_structure)) != 0)
      debug(1, "error unmapping shared memory");
    // shm_open cleanup
    if (shm_unlink(STORAGE_ID) == -1)
      debug(1, "error unlinking shared memory \"%s\"", STORAGE_ID);
  }
  if (epoll_fd != -1)
    close(epoll_fd);

  debug(1, "goodbye");
}

void intHandler(__attribute__((unused)) int k) {
  debug(1, "exit on SIGINT");
  exit(EXIT_SUCCESS);
}

void termHandler(__attribute__((unused)) int k) {
  debug(1, "exit on SIGTERM");
  exit(EXIT_SUCCESS);
}

int main(void) {
  debug_init(DEBUG_LEVEL, 0, 1, 1);
  debug(1, "startup");
  atexit(goodbye);

  t4_t1_difference_reported = 0;
  epoll_fd = -1;
  clocks = NULL;
  shared_memory = NULL;
  // memset(sources,0,sizeof(sources));
  // level 0 is no messages, level 3 is most messages -- see debug.h

  // control-c (SIGINT) cleanly
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = intHandler;
  sigaction(SIGINT, &act, NULL);

  // terminate (SIGTERM)
  struct sigaction act2;
  memset(&act2, 0, sizeof(struct sigaction));
  act2.sa_handler = termHandler;
  sigaction(SIGTERM, &act2, NULL);

  ssize_t recv_len;

  char buf[BUFLEN];

  int status;

  struct __attribute__((__packed__)) ptp_common_message_header {
    uint8_t transportSpecificAndMessageID; // 0x11
    uint8_t reservedAndVersionPTP;         // 0x02
    uint16_t messageLength;
    uint8_t domainNumber;        // 0
    uint8_t reserved_b;          // 0
    uint16_t flags;              // 0x0608
    uint64_t correctionField;    // 0
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

  pthread_mutexattr_t shared;
  int err;

  struct ptp_delay_req_message m;

  int so_timestamping_flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE |
                              SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
                              SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
  // int so_timestamping_flags =  SOF_TIMESTAMPING_RX_SOFTWARE ;

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

      if (ret == 0)
        ret = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags,
                         sizeof(so_timestamping_flags));

      /*
                              struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv) == -1)
              debug(1, "Error %d setting outgoing timeout.", errno);
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv) == -1)
              debug(1, "Error %d setting incoming timeout.", errno);
      */
      int flags = fcntl(fd, F_GETFL);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      /*
            int val = 0;
            socklen_t len = sizeof(val);
            if (getsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, &len) < 0)
              fprintf(stderr, "%s: %s\n", "getsockopt SO_TIMESTAMPING", strerror(errno));
            else
              fprintf(stderr, "SO_TIMESTAMPING requested: %d, obtained: %d\n",
         so_timestamping_flags, val);
      */
      /*
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
      */

      // one of the address families will fail on some systems that
      // report its availability. do not complain.

      if (ret) {
        die("unable to listen on %s port %d. The error is: \"%s\". Daemon must run as root. Or is "
            "a "
            "separate PTP daemon running?",
            p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 320, strerror(errno));
      } else {

        debug(2, "listening on %s port %d.", p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 319);
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

      if (ret == 0)
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags,
                   sizeof(so_timestamping_flags));

      int flags = fcntl(fd, F_GETFL);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);

      /*
           struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv) == -1)
              debug(1, "Error %d setting send outgoing timeout.", errno);
      */

      /*      int val;
            socklen_t len = sizeof(val);
            if (getsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, &len) < 0)
              fprintf(stderr, "%s: %s\n", "getsockopt SO_TIMESTAMPING", strerror(errno));
            else
              fprintf(stderr, "SO_TIMESTAMPING requested: %d, obtained: %d\n",
         so_timestamping_flags, val);
      */
      /*
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
      */
      // one of the address families will fail on some systems that
      // report its availability. do not complain.

      if (ret) {
        die("unable to listen on %s port %d. The error is: \"%s\". Daemon must run as root. Or is "
            "a "
            "separate PTP daemon running?",
            p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 320, strerror(errno));
        exit(1);
      } else {
        debug(2, "listening on %s port %d.", p->ai_family == AF_INET6 ? "IPv6" : "IPv4", 320);
        sockets[sockets_open].number = fd;
        sockets[sockets_open++].port = 320;
      }
    }
  }

  freeaddrinfo(info);

  // open a shared memory interface.
  int shm_fd = -1;

  mode_t oldumask = umask(0);
  struct group *grp = getgrnam("nqptp");
  if (grp == NULL) {
    inform("the group \"nqptp\" was not found, will try \"root\" group instead.");
  }
  shm_fd = shm_open(STORAGE_ID, O_RDWR | O_CREAT, 0666);
  if (shm_fd == -1) {
    die("cannot open shared memory \"%s\".", STORAGE_ID);
  }
  (void)umask(oldumask);

  if (fchown(shm_fd, -1, grp != NULL ? grp->gr_gid : 0) < 0) {
    warn("failed to set ownership of shared memory \"%s\" to group \"nqptp\".", STORAGE_ID);
  }

  if (ftruncate(shm_fd, sizeof(struct shm_structure)) == -1) {
    die("failed to set size of shared memory \"%s\".", STORAGE_ID);
  }
  shared_memory =
      (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                   MAP_LOCKED | MAP_SHARED, shm_fd, 0);
  if (shared_memory == (struct shm_structure *)-1) {
    die("failed to mmap shared memory \"%s\".", STORAGE_ID);
  }

  if ((close(shm_fd) == -1)) {
    warn("error closing \"/nqptp\" after mapping.");
  }

  // zero it
  memset(shared_memory, 0, sizeof(struct shm_structure));
  shared_memory->size_of_clock_array = MAX_SHARED_CLOCKS;
  shared_memory->version = NQPTP_SHM_STRUCTURES_VERSION;

  /*create mutex attr */
  err = pthread_mutexattr_init(&shared);
  if (err != 0) {
    die("mutex attribute initialization failed - %s.", strerror(errno));
  }
  pthread_mutexattr_setpshared(&shared, 1);
  /*create a mutex */
  err = pthread_mutex_init((pthread_mutex_t *)&shared_memory->shm_mutex, &shared);
  if (err != 0) {
    die("mutex initialization failed - %s.", strerror(errno));
  }

  if (sockets_open > 0) {

#define MAX_EVENTS 128
    struct epoll_event event;
    int epoll_fd = epoll_create(32);

    if (epoll_fd == -1)
      die("Failed to create epoll file descriptor\n");

    unsigned int ep;
    for (ep = 0; ep < sockets_open; ep++) {
      // if (sockets[s].number > smax)
      // smax = sockets[s].number;
      event.events = EPOLLIN;
      event.data.fd = sockets[ep].number;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockets[ep].number, &event) != 0)
        die("failed to add socket %d to epoll", sockets[ep].number);
      else
        debug(3, "add socket %d to epoll", sockets[ep].number);
    }

    while (1) {
      /*
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

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            int retval = select(smax + 1, &readSockSet, NULL, NULL, &timeout);
      */

      struct epoll_event events[MAX_EVENTS];
      int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
      uint64_t reception_time = get_time_now(); // use this if other methods fail

      int t;
      for (t = 0; t < event_count; t++) {
        int socket_number = events[t].data.fd;
        {

          SOCKADDR from_sock_addr;
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

          recv_len = recvmsg(socket_number, &msg, MSG_DONTWAIT);

          if (recv_len == -1) {
            if (errno == EAGAIN) {
              usleep(1000); // this can happen, it seems...
            } else {
              debug(1, "recvmsg() error %d", errno);
            }
          } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
            debug(3, "Received %d bytes control message on reception.", msg.msg_controllen);
            // get the time
            int level, type;
            struct cmsghdr *cm;
            struct timespec *ts = NULL;
            for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
              level = cm->cmsg_level;
              type = cm->cmsg_type;
              if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
                /*
                                  struct timespec *stamp = (struct timespec *)CMSG_DATA(cm);
                                  fprintf(stderr, "SO_TIMESTAMPING Rx: ");
                                  fprintf(stderr, "SW %ld.%09ld\n", (long)stamp->tv_sec,
                   (long)stamp->tv_nsec); stamp++;
                                  // skip deprecated HW transformed
                                  stamp++;
                                  fprintf(stderr, "SO_TIMESTAMPING Rx: ");
                                  fprintf(stderr, "HW raw %ld.%09ld\n", (long)stamp->tv_sec,
                   (long)stamp->tv_nsec);
                */
                ts = (struct timespec *)CMSG_DATA(cm);
                reception_time = ts->tv_sec;
                reception_time = reception_time * 1000000000;
                reception_time = reception_time + ts->tv_nsec;
              } else {
                debug(3, "Can't establish a reception time -- falling back on get_time_now().");
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

            //              if ((sender_port == sockets[t].port) && (connection_ip_family ==
            //              AF_INET)) {
            if (sender_port == sockets[t].port) {
              char sender_string[256];
              memset(sender_string, 0, sizeof(sender_string));
              inet_ntop(connection_ip_family, sender_addr, sender_string, sizeof(sender_string));
              // now, find or create a record for this ip / clock_id combination
              struct ptp_common_message_header *mt = (struct ptp_common_message_header *)buf;
              uint64_t packet_clock_id = nctohl(&mt->clockIdentity[0]);
              uint64_t packet_clock_id_low = nctohl(&mt->clockIdentity[4]);
              packet_clock_id = packet_clock_id << 32;
              packet_clock_id = packet_clock_id + packet_clock_id_low;

              struct ptpSource *the_clock = find_source(sender_string, packet_clock_id);
              if ((the_clock == NULL) && ((buf[0] & 0xF) == Sync)) {
                the_clock = create_source(sender_string, packet_clock_id);
              }
              if (the_clock != NULL) {
                switch (buf[0] & 0xF) {
                case Sync: { // if it's a sync
                  struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
                  int ck;
                  int non_empty_origin_timestamp = 0;
                  for (ck = 0; ck < 10; ck++) {
                    if (msg->sync.originTimestamp[ck] != 0) {
                      non_empty_origin_timestamp = (non_empty_origin_timestamp | 1);
                    }
                  }
                  if (non_empty_origin_timestamp != 0)
                    debug(1, "Sync Origin Timestamp!");
                  if (msg->header.correctionField != 0)
                    debug(3, "correctionField: %" PRIx64 ".", msg->header.correctionField);
                  // debug(3, "SYNC %u.", ntohs(msg->header.sequenceId));
                  int discard_sync = 0;

                  if ((the_clock->current_stage != nothing_seen) &&
                      (the_clock->current_stage != waiting_for_sync)) {

                    // here, we have an unexpected SYNC. It could be because the
                    // previous transaction sequence failed for some reason
                    // But, if that is so, the SYNC will have a newer sequence number
                    // so, ignore it if it's older.

                    uint16_t new_sync_sequence_number = ntohs(msg->header.sequenceId);
                    int16_t sequence_number_difference =
                        (the_clock->sequence_number - new_sync_sequence_number);
                    if ((sequence_number_difference > 0) && (sequence_number_difference < 8))
                      discard_sync = 1;

                    debug(3,
                          "Sync %u expecting to be in state nothing_seen (%u) or waiting_for_sync "
                          "(%u). Stage error -- "
                          "current state is %u, sequence %u.%s %s",
                          ntohs(msg->header.sequenceId), nothing_seen, waiting_for_sync,
                          the_clock->current_stage, the_clock->sequence_number,
                          discard_sync ? " Discarded because it is older." : "", the_clock->ip);
                  }
                  if (discard_sync == 0) {

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

                    // here we generate the local clock ID
                    // by getting the first valid MAC address

                    char local_clock_id[8];
                    int len = 0;
                    struct ifaddrs *ifaddr = NULL;
                    struct ifaddrs *ifa = NULL;

                    if ((status = getifaddrs(&ifaddr) == -1)) {
                      die("getifaddrs: %s", gai_strerror(status));
                    } else {
                      int found = 0;
                      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                        if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
                          struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                          if ((strcmp(ifa->ifa_name, "lo") != 0) && (found == 0)) {
                            len = s->sll_halen;
                            memcpy(local_clock_id, &s->sll_addr, len);
                            found = 1;
                          }
                        }
                      }
                      freeifaddrs(ifaddr);
                    }
                    // if the length of the MAC address is 6 we need to doctor it a little
                    // See Section 7.5.2.2.2 IEEE EUI-64 clockIdentity values, NOTE 2

                    if (len == 6) { // i.e. an EUI-48 MAC Address
                      local_clock_id[7] = local_clock_id[5];
                      local_clock_id[6] = local_clock_id[4];
                      local_clock_id[5] = local_clock_id[3];
                      local_clock_id[3] = 0xFF;
                      local_clock_id[4] = 0xFE;
                    }
                    // finally, copy this into the record
                    memcpy(&m.header.clockIdentity, local_clock_id, 8);

                    struct msghdr header;
                    struct iovec io;
                    memset(&header, 0, sizeof(header));
                    memset(&io, 0, sizeof(io));
                    header.msg_name = &from_sock_addr;
                    header.msg_namelen = sizeof(from_sock_addr);
                    header.msg_iov = &io;
                    header.msg_iov->iov_base = &m;
                    header.msg_iov->iov_len = sizeof(m);
                    header.msg_iovlen = 1;
                    uint64_t transmission_time = get_time_now(); // in case nothing better works
                    if ((sendmsg(socket_number, &header, 0)) == -1) {
                      debug(1, "Error in sendmsg [errno = %d]", errno);
                    }

                    // Obtain the sent packet timestamp.
                    char data[256];
                    struct msghdr msg;
                    struct iovec entry;
                    struct sockaddr_in from_addr;
                    struct {
                      struct cmsghdr cm;
                      char control[512];
                    } control;

                    memset(&msg, 0, sizeof(msg));
                    msg.msg_iov = &entry;
                    msg.msg_iovlen = 1;
                    entry.iov_base = data;
                    entry.iov_len = sizeof(data);
                    msg.msg_name = (caddr_t)&from_addr;
                    msg.msg_namelen = sizeof(from_addr);
                    msg.msg_control = &control;
                    msg.msg_controllen = sizeof(control);
                    if (recvmsg(socket_number, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) == -1) {
                      debug(3, "recvmsg error %d attempting to retrieve the sent packet timestamp.",
                            errno);
                      // can't get the transmission time directly
                      // possibly because it's not implemented
                      struct timespec tv_ioctl;
                      tv_ioctl.tv_sec = 0;
                      tv_ioctl.tv_nsec = 0;
                      int error = ioctl(socket_number, SIOCGSTAMPNS, &tv_ioctl);
                      if (error == 0) { // somnetimes, even this doesn't work, so we fall back on
                                        // the earlier get_time_now();
                        transmission_time = tv_ioctl.tv_sec;
                        transmission_time = transmission_time * 1000000000;
                        transmission_time = transmission_time + tv_ioctl.tv_nsec;
                      }
                    } else {
                      // get the time
                      int level, type;
                      struct cmsghdr *cm;
                      struct timespec *ts = NULL;
                      for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
                        level = cm->cmsg_level;
                        type = cm->cmsg_type;
                        if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
                          /*
                                                      struct timespec *stamp = (struct timespec
                             *)CMSG_DATA(cm); fprintf(stderr, "SO_TIMESTAMPING Tx: ");
                                                      fprintf(stderr, "SW %ld.%09ld\n",
                             (long)stamp->tv_sec, (long)stamp->tv_nsec); stamp++;
                                                      // skip deprecated HW transformed
                                                      stamp++;
                                                      fprintf(stderr, "SO_TIMESTAMPING Tx: ");
                                                      fprintf(stderr, "HW raw %ld.%09ld\n",
                             (long)stamp->tv_sec, (long)stamp->tv_nsec);
                          */
                          ts = (struct timespec *)CMSG_DATA(cm);
                          transmission_time = ts->tv_sec;
                          transmission_time = transmission_time * 1000000000;
                          transmission_time = transmission_time + ts->tv_nsec;
                        } else {
                          debug(3, "Can't establish a transmission time! Falling back on "
                                   "get_time_now().");
                        }
                      }
                    }

                    // clang-format off
                    /*
                    // fprintf(stderr, "DREQ to %s\n", the_clock->ip);
                    if (sendto(sockets[t].number, &m, sizeof(m), 0,
                               (const struct sockaddr *)&from_sock_addr,
                               from_sock_addr_length) == -1) {
                      fprintf(stderr, "sendto: %s\n", strerror(errno));
                      return 4;
                    }
                    */
                    // clang-format on

                    the_clock->t3 = transmission_time;
                    // int64_t ttd = transmission_time - the_clock->t3;
                    // fprintf(stderr, "transmission time delta: %f.\n", ttd*0.000000001);

                    the_clock->current_stage = sync_seen;
                  }
                } break;

                case Follow_Up: {
                  struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
                  if ((the_clock->current_stage == sync_seen) &&
                      (the_clock->sequence_number == ntohs(msg->header.sequenceId))) {
                    if (the_clock->at_least_one_follow_up_seen == 0)
                      debug(1, "Clock \"%" PRIx64 "\" at %s has seen a first Follow_Up",
                            the_clock->clock_id, &the_clock->ip);
                    the_clock->at_least_one_follow_up_seen = 1;
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

                    // we will use t1 as the distant reference until we get a Delay_Resp, which
                    // should be more accurate. Is some casses, though, t4 and t1 are the same.
                    update_clock_interface(the_clock);

                  } else {
                    if (the_clock->current_stage != waiting_for_sync) {

                      debug(3,
                            "Follow_Up %u expecting to be in state sync_seen (%u). Stage error -- "
                            "current state is %u, sequence %u. Ignoring it. %s",
                            ntohs(msg->header.sequenceId), sync_seen, the_clock->current_stage,
                            the_clock->sequence_number, the_clock->ip);
                    }
                  }
                } break;
                case Delay_Resp: {
                  struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;
                  if ((the_clock->current_stage == follow_up_seen) &&
                      (the_clock->sequence_number == ntohs(msg->header.sequenceId))) {
                    if (the_clock->at_least_one_delay_resp_seen == 0)
                      debug(1, "%" PRIx64 " at %s has seen a first Delay_Resp", the_clock->clock_id,
                            &the_clock->ip);
                    the_clock->at_least_one_delay_resp_seen = 1;
                    uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
                    uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
                    uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
                    uint64_t receiveTimestamp = seconds_hi;
                    receiveTimestamp = receiveTimestamp << 32;
                    receiveTimestamp = receiveTimestamp + seconds_low;
                    receiveTimestamp = receiveTimestamp * 1000000000L;
                    receiveTimestamp = receiveTimestamp + nanoseconds;
                    the_clock->t4 = receiveTimestamp;

                    /*
                    // reference: Figure 12
                    (t4 - t1) [always positive, a difference of two distant clock times]
                    less (t3 -t2) [always positive, a difference of two local clock times]
                    is equal to t(m->s) + t(s->m), thus twice the propagation time
                    assuming symmetrical delays
                    */
                    // all devices tested return the same value for t4 and t1. Go figure.
                    if ((the_clock->t4 != the_clock->t1) && (t4_t1_difference_reported == 0)) {
                      inform("Clock \"%" PRIx64
                             "\" at \"%s\" is providing different t4 and t1 figures!",
                             the_clock->clock_id, &the_clock->ip);
                      t4_t1_difference_reported = 1;
                    }
                    the_clock->current_stage = nothing_seen;
                  } else {
                    if (the_clock->current_stage != waiting_for_sync) {

                      debug(3,
                            "Delay_Resp %u expecting to be in state follow_up_seen (%u). Stage "
                            "error -- "
                            "current state is %u, sequence %u. Ignoring it. %s",
                            ntohs(msg->header.sequenceId), follow_up_seen, the_clock->current_stage,
                            the_clock->sequence_number, the_clock->ip);
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
      deactivate_old_sources(reception_time);
    }
    // here, invalidate records and entries that are out of date
    // uint64_t tn = get_time_now();
  }

  // here, close all the sockets...

  return 0;
}
