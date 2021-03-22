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

#define DEBUG_LEVEL 0

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
  char *ip; // ipv4 or ipv6
  uint64_t clock_id;
  uint16_t sequence_number;
  enum stage current_stage;
  uint64_t t1, t2, t3, t4, t5, previous_offset, previous_estimated_offset;
  struct timing_samples samples[MAX_TIMING_SAMPLES];
  int vacant_samples; // the number of elements in the timing_samples array that are not yet used
  int next_sample_goes_here; // point to where in the timing samples array the next entries should
                             // go
  int shared_clock_number;   // which entry to use in the shared memory, could be -1!
  uint64_t sample_number;    // should roll over in 2^61 seconds!
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
struct shm_structure *shared_memory = NULL;

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

struct ptpSource *findOrCreateSource(struct ptpSource **list, char *ip, uint64_t clock_id,
                                     uint8_t message_type) {
  struct ptpSource *response;
  struct ptpSource **insertion_point = list; // in case the list is empty
  struct ptpSource *crawler = *list;
  if (crawler == NULL) {
    debug(3, "No clocks recorded");
    insertion_point = list;
  } else {
    while ((crawler->next != NULL) &&
           ((crawler->clock_id != clock_id) || (strcasecmp(ip, crawler->ip) != 0))) {
      crawler = crawler->next;
    }
    if ((crawler->clock_id == clock_id) && (strcasecmp(ip, crawler->ip) == 0)) {
      // found, so no insertion
      insertion_point = NULL;
    } else {
      // not found, so we are on the last item. Add a new one on to the end.
      insertion_point = &crawler->next;
    }
  }
  // here, if the insertion point is null, then
  // the record is pointed to by crawler
  // otherwise, add a new record at the insertion point
  if (insertion_point == NULL) {
    response = crawler;
  } else {
    // only create a record for a Sync message
    if (message_type == Sync) {
      response = (struct ptpSource *)malloc(sizeof(ptpSource));
      if (response != NULL) {
        memset((void *)response, 0, sizeof(ptpSource));
        response->ip = strdup(ip);
        response->clock_id = clock_id;
        response->vacant_samples = MAX_TIMING_SAMPLES; // no valid samples yet
        response->shared_clock_number = -1;            // none allocated yet. Hacky
        *insertion_point = response;
        debug(2,
              "Clock record created for Clock ID: '%" PRIu64 "', aka '%" PRIu64 "', aka '%" PRIx64
              "' at %s.",
              clock_id, clock_id, clock_id, ip);
      }
    } else {
      response = NULL;
    }
  }
  return response;
}

void deleteObseleteClockRecords(struct ptpSource **list, uint64_t time_now) {
  // debug(1,"delete -- time now: % " PRIx64 ".", time_now);

  struct ptpSource **temp = list;
  while (*temp != NULL) {
    struct ptpSource *p = *temp;
    int64_t time_since_last_use = time_now - p->t2; // this is the time of the last sync record
    debug(2, "checking record for Clock ID %" PRIx64 " at %s. Time difference is %" PRId64 ".",
          p->clock_id, p->ip, time_since_last_use);
    if (time_since_last_use > 15000000000) {
      debug(2, "delete record for Clock ID %" PRIx64 " at %s.", p->clock_id, p->ip);
      if (p->shared_clock_number != -1) {
        int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
        if (rc != 0)
          debug(1, "Can't acquire mutex to delete a clock!");
        memset(&shared_memory->clocks[p->shared_clock_number], 0, sizeof(struct clock_source));
        rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
        if (rc != 0)
          debug(1, "Can't release mutex after deleting a clock!");
      }

      *temp = p->next;
      free(p->ip); // the IP was strdup'ed in
      free(p);
    } else {
      temp = &p->next;
    }
  }
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
  // level 0 is no messages, level 3 is most messages -- see debug.h
  debug_init(DEBUG_LEVEL, 0, 1, 1);
  debug(1, "startup");
  atexit(goodbye);

  // control-c (SIGINT) cleanly
  struct sigaction act;
  act.sa_handler = intHandler;
  sigaction(SIGINT, &act, NULL);

  // terminate (SIGTERM)
  struct sigaction act2;
  act2.sa_handler = termHandler;
  sigaction(SIGTERM, &act2, NULL);

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

  int next_free_clock_source_entry = 0;
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
        setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags,
                   sizeof(so_timestamping_flags));

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
      uint64_t reception_time = get_time_now(); // use this if other methods fail
      if (retval > 0) {

        unsigned t;
        for (t = 0; t < sockets_open; t++) {
          if (FD_ISSET(sockets[t].number, &readSockSet)) {

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

            recv_len = recvmsg(sockets[t].number, &msg, 0);

            if (recv_len == -1) {
              debug(1, "recvfrom() error");
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
                struct ptpSource *the_clock =
                    findOrCreateSource(&clocks, sender_string, packet_clock_id,
                                       buf[0] & 0xF); // only create a record for a SYNC
                if (the_clock != NULL) {
                  switch (buf[0] & 0xF) {
                  case Sync: { // if it's a sync
                    struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
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

                      debug(
                          3,
                          "Sync %u expecting to be in state nothing_seen (%u) or waiting_for_sync "
                          "(%u). Stage error -- "
                          "current state is %u, sequence %u.%s %s",
                          ntohs(msg->header.sequenceId), nothing_seen, waiting_for_sync,
                          the_clock->current_stage, the_clock->sequence_number,
                          discard_sync ? " Discarded because it is older." : "", the_clock->ip);
                    }
                    if (discard_sync == 0) {

                      // if necessary, initialise a new shared clock record
                      // hacky.
                      if (the_clock->shared_clock_number == -1) {
                        if (next_free_clock_source_entry == MAX_SHARED_CLOCKS)
                          die("No more shared clocks!");
                        // associate and initialise a shared clock record
                        int i = 0;
                        while ((shared_memory->clocks[i].valid != 0) && (i < MAX_SHARED_CLOCKS)) {
                          i++;
                        }
                        if (i == MAX_SHARED_CLOCKS)
                          die("All %d clock entries are in use -- no more available!",
                              MAX_SHARED_CLOCKS);
                        the_clock->shared_clock_number = i;
                        int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
                        if (rc != 0)
                          die("Can't acquire mutex to initialise a clock!");
                        memset(&shared_memory->clocks[i], 0, sizeof(struct clock_source));
                        strncpy((char *)&shared_memory->clocks[i].ip, the_clock->ip,
                                INET6_ADDRSTRLEN - 1);
                        shared_memory->clocks[i].clock_id = the_clock->clock_id;
                        shared_memory->clocks[i].valid = 1;
                        rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
                        if (rc != 0)
                          die("Can't release mutex after initialising a clock!");
                        debug(2,
                              "shared memory clock entry %d created for Clock ID: '%" PRIx64
                              "' at %s.",
                              i, the_clock->clock_id, the_clock->ip);
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
                      if ((sendmsg(sockets[t].number, &header, 0)) == -1) {
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
                      if (recvmsg(sockets[t].number, &msg, MSG_ERRQUEUE) == -1) {
                        // can't get the transmission time directly
                        // possibly because it's not implemented
                        struct timespec tv_ioctl;
                        tv_ioctl.tv_sec = 0;
                        tv_ioctl.tv_nsec = 0;
                        int error = ioctl(sockets[t].number, SIOCGSTAMPNS, &tv_ioctl);
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

                        debug(
                            3,
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
                      // some devices return the same value for t4 and t1. Go figure.
                      int64_t distant_time_difference = the_clock->t4 - the_clock->t1;
                      int64_t local_time_difference = the_clock->t3 - the_clock->t2;
                      int64_t double_propagation_time =
                          distant_time_difference - distant_time_difference; // better be positive
                      if (distant_time_difference != 0)
                        debug(3,
                              "distant_time_difference: %" PRId64
                              ", local_time_difference: %" PRId64
                              " , double_propagation_time %" PRId64 ".",
                              distant_time_difference, local_time_difference,
                              double_propagation_time);

                      the_clock->t5 =
                          reception_time; // t5 - t3 gives us the out-and-back time locally
                                          // -- an instantaneous quality index
                                          // t5 - t2 gives us an overall interchange time
                                          // from the Sync to the Delay Resp

                      if ((the_clock->t5 - the_clock->t2) < 25 * 1000000) {
                        if ((the_clock->t4 - the_clock->t1) < 60 * 1000000) {

                          // calculate delay and calculate offset
                          // fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ",
                          // t4:
                          // %" PRIx64
                          // ".\n",t1,t2,t3,t4); fprintf(stderr, "nominal remote transaction time:
                          // %" PRIx64 " =
                          // %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n",
                          // t4-t1, t4-t1, t3-t2, t3-t2);

                          uint64_t instantaneous_offset = the_clock->t1 - the_clock->t2;
                          int64_t change_in_offset =
                              instantaneous_offset - the_clock->previous_offset;

                          // now, decide whether to keep the sample for averaging, etc.
                          the_clock->sample_number++;
                          if (the_clock->sample_number ==
                              16) { // discard the approx first two seconds!
                                    // remove previous samples before this number
                            the_clock->vacant_samples =
                                MAX_TIMING_SAMPLES; // invalidate all the previous samples used for
                                                    // averaging, etc.
                            the_clock->next_sample_goes_here = 0;
                          }

                          int64_t discontinuity_threshold = 250000000; // nanoseconds
                          if ((change_in_offset > discontinuity_threshold) ||
                              (change_in_offset < (-discontinuity_threshold))) {

                            debug(3, "large discontinuity of %+f seconds detected, sequence %u.",
                                  change_in_offset * 0.000000001, the_clock->sequence_number);
                            the_clock->vacant_samples =
                                MAX_TIMING_SAMPLES; // invalidate all the previous samples used for
                                                    // averaging, etc.
                            the_clock->next_sample_goes_here = 0;
                          }

                          // now, store the remote and local times in the array
                          the_clock->samples[the_clock->next_sample_goes_here].local =
                              the_clock->t2;
                          the_clock->samples[the_clock->next_sample_goes_here].remote =
                              the_clock->t1;
                          uint64_t diff = the_clock->t1 - the_clock->t2;
                          the_clock->samples[the_clock->next_sample_goes_here]
                              .local_to_remote_offset = diff;
                          the_clock->next_sample_goes_here++;
                          if (the_clock->next_sample_goes_here == MAX_TIMING_SAMPLES)
                            the_clock->next_sample_goes_here = 0;
                          if (the_clock->vacant_samples > 0)
                            the_clock->vacant_samples--;

                          uint64_t estimated_offset = instantaneous_offset;

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
                        uint64_t estimated_offset = remote_estimate - the_clock->t2;
*/
                          // clang-format on

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

                          // just to keep the print line happy
                          // long double gradient = 1.0;
                          // uint64_t offset = the_clock->t1 - the_clock->t2;

                          // clang-format on

                          // clang-format off
/*
													// here, use a Savitzky–Golay filter to smooth the last 9 offsets
													// see https://en.wikipedia.org/wiki/Savitzky–Golay_filter

													int window_size = 9;
													int coefficients[20] = {15,-55,30,135,179,135,30,-55,15};
													int normalisation = 429;

													if ((MAX_TIMING_SAMPLES - the_clock->vacant_samples) >= window_size) {
														uint64_t sg[20];
														int s = the_clock->next_sample_goes_here;
														int f;
														for (f = window_size; f > 0; f--) {
															s--;
															if (s < 0)
																s = MAX_TIMING_SAMPLES - 1;
															sg[f-1] = the_clock->samples[s].local_to_remote_offset;

														}

														long double yj = 0.0;
														for (f = 0; f < window_size; f++) {
															uint64_t ho = sg[f];
															// ho = ho >> 12;
															//fprintf(stderr, "element: %d is %" PRIx64 ".\n", f, ho);
															yj = yj + (1.0 * ho) * coefficients[f];
														}
														yj = yj / normalisation;
														estimated_offset = yj;
														//fprintf(stderr, "estimated_offset: %" PRIx64 ".\n", estimated_offset);
													}
													// just to keep the print line happy
													long double gradient = 1.0;
													int sample_count = window_size;
*/
                          // clang-format on

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
                          shared_memory->clocks[the_clock->shared_clock_number].local_time =
                              the_clock->t2;
                          shared_memory->clocks[the_clock->shared_clock_number].source_time =
                              estimated_offset + the_clock->t2;
                          shared_memory->clocks[the_clock->shared_clock_number]
                              .local_to_source_time_offset = estimated_offset;
                          rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
                          if (rc != 0)
                            warn("Can't release mutex after updating a clock!");

                          // clang-format off

                            debug(2,"id: %20" PRIu64 ", time: 0x%" PRIx64
                                    ", offset: %" PRIx64
                                    ", variation: %+f, turnaround: %f, ip: %s, sequence: %u samples: %d.",
                                    the_clock->clock_id, the_clock->t2 + estimated_offset,
                                    estimated_offset,
                                    variation * 0.000000001,
                                    (the_clock->t5 - the_clock->t2) * 0.000000001,
                                    the_clock->ip, the_clock->sequence_number, sample_count);

                        the_clock->previous_estimated_offset = estimated_offset;
                        the_clock->previous_offset = instantaneous_offset;
                      } else {
                         debug(3,
                                "t4 - t1 (sync and delay response) time %f is too long. Discarding. %s", (the_clock->t4 - the_clock->t1)*0.000000001,
                                the_clock->ip);
                      }
                    } else {
                      // fprintf(stderr, "t5 - t2 time %f (total transaction time) is too long.
                      // Discarding. %s\n", (the_clock->t5 - the_clock->t2)*0.000000001,
                      //        the_clock->ip);
                    }
                    the_clock->current_stage = nothing_seen;
                  } else {
                    if (the_clock->current_stage != waiting_for_sync) {

                                              debug(3,
                                                      "Delay_Resp %u expecting to be in state follow_up_seen (%u). Stage " "error -- " "current state is %u, sequence %u. Ignoring it. %s", ntohs(msg->header.sequenceId), follow_up_seen,
                                                      the_clock->current_stage,
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

      } else if (retval < 0) {
        // check errno/WSAGetLastError(), call perror(), etc ...
      }
      // here, invalidate records and entries that are out of date
      uint64_t tn = get_time_now();
      deleteObseleteClockRecords(&clocks, tn);
    }
  }

  // here, close all the sockets...

  return 0;
}
