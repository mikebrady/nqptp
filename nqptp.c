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

#define DEBUG_LEVEL 1

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
  waiting_for_sync,
  sync_seen,
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

#define MAX_TIMING_SAMPLES 1
struct timing_samples {
  uint64_t local, remote, local_to_remote_offset;
} timing_samples;

struct clock_private_info {
  uint16_t sequence_number;
  uint16_t in_use;
  enum stage current_stage;
  uint64_t t2;

} clock_private_info;

#define BUFLEN 4096 // Max length of buffer

#define MAX_OPEN_SOCKETS 32 // up to 32 sockets open on ports 319 and 320

struct socket_info {
  int number;
  uint16_t port;
};
struct clock_private_info clocks_private[MAX_CLOCKS];

struct socket_info sockets[MAX_OPEN_SOCKETS];
unsigned int sockets_open =
    0; // also doubles as where to put next one, as sockets are never closed.
struct shm_structure *shared_memory = NULL;
int epoll_fd;

// struct sockaddr_in6 is bigger than struct sockaddr.
#ifdef AF_INET6
#define SOCKADDR struct sockaddr_storage
#define SAFAMILY ss_family
#else
#define SOCKADDR struct sockaddr
#define SAFAMILY sa_family
#endif

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

int find_source(char *sender_string, uint64_t packet_clock_id,
                struct clock_source *clocks_shared_info,
                struct clock_private_info *clocks_private_info) {
  // return the index of the clock in the clock information arrays or -1
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if ((clocks_private_info[i].in_use != 0) &&
        (clocks_shared_info[i].clock_id == packet_clock_id) &&
        (strcasecmp(sender_string, (const char *)&clocks_shared_info[i].ip) == 0))
      found = 1;
    else
      i++;
  }
  if (found == 1)
    response = i;
  return response;
}

int create_source(char *sender_string, uint64_t packet_clock_id,
                  struct clock_source *clocks_shared_info,
                  struct clock_private_info *clocks_private_info) {
  // return the index of a clock entry in the clock information arrays or -1 if full
  // initialise the entries in the shared and private arrays
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if (clocks_private_info[i].in_use == 0)
      found = 1;
    else
      i++;
  }

  if (found == 1) {
    response = i;
    int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
    if (rc != 0)
      warn("Can't acquire mutex to activate a new  clock!");
    memset(&clocks_shared_info[i], 0, sizeof(struct clock_source));
    strncpy((char *)&clocks_shared_info[i].ip, sender_string, 64 - 1);
    clocks_shared_info[i].clock_id = packet_clock_id;
    rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
    if (rc != 0)
      warn("Can't release mutex after activating a new clock!");

    memset(&clocks_private_info[i], 0, sizeof(struct clock_private_info));
    clocks_private_info[i].in_use = 1;
    clocks_private_info[i].t2 = 0;
    clocks_private_info[i].current_stage = waiting_for_sync;
    debug(1, "activated source %d with clock_id %" PRIx64 " on ip: %s.", i,
          clocks_shared_info[i].clock_id, &clocks_shared_info[i].ip);
  } else {
    die("Clock tables full!");
  }
  return response;
}

void deactivate_old_sources(uint64_t reception_time, struct clock_source *clocks_shared_info,
                            struct clock_private_info *clocks_private_info) {
  debug(3, "deactivate_old_sources");
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    if (clocks_private_info[i].in_use != 0) {
      int64_t time_since_last_sync = reception_time - clocks_private_info[i].t2;
      if (time_since_last_sync > 60000000000) {
        debug(1, "deactivating source %d with clock_id %" PRIx64 " on ip: %s.", i,
              clocks_shared_info[i].clock_id, &clocks_shared_info[i].ip);
        int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
        if (rc != 0)
          warn("Can't acquire mutex to deactivate a clock!");
        memset(&clocks_shared_info[i], 0, sizeof(struct clock_source));
        rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
        if (rc != 0)
          warn("Can't release mutex after deactivating a clock!");
        memset(&clocks_private_info[i], 0, sizeof(struct clock_private_info));
      }
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

  epoll_fd = -1;
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

  // this is the extra part for an Announce message
  struct __attribute__((__packed__)) ptp_announce {
    uint8_t originTimestamp[10];
    uint16_t currentUtcOffset;
    uint8_t reserved1;
    uint8_t grandmasterPriority1;
    uint32_t grandmasterClockQuality;
    uint8_t grandmasterPriority2;
    uint8_t grandmasterIdentity[8];
    uint16_t stepsRemoved;
    uint8_t timeSource;
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

  struct __attribute__((__packed__)) ptp_announce_message {
    struct ptp_common_message_header header;
    struct ptp_announce announce;
  };

  pthread_mutexattr_t shared;
  int err;

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

      int flags = fcntl(fd, F_GETFL);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);

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
        sockets[sockets_open].port = 319;
        sockets_open++;
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
        sockets[sockets_open].port = 320;
        sockets_open++;
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
  shared_memory->size_of_clock_array = MAX_CLOCKS;
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

          if (recv_len != -1)
            debug_print_buffer(2, buf, recv_len);

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

            // check here if the sender port and receiver port are the same
            // find the socket in the socket list
            uint16_t receiver_port = 0;
            unsigned int jp;
            for (jp = 0; jp < sockets_open; jp++) {
              if (socket_number == sockets[jp].number)
                receiver_port = sockets[jp].port;
            }

            if (sender_port == receiver_port) {

              char sender_string[256];
              memset(sender_string, 0, sizeof(sender_string));
              inet_ntop(connection_ip_family, sender_addr, sender_string, sizeof(sender_string));
              // now, find or create a record for this ip / clock_id combination
              struct ptp_common_message_header *mt = (struct ptp_common_message_header *)buf;
              uint64_t packet_clock_id = nctohl(&mt->clockIdentity[0]);
              uint64_t packet_clock_id_low = nctohl(&mt->clockIdentity[4]);
              packet_clock_id = packet_clock_id << 32;
              packet_clock_id = packet_clock_id + packet_clock_id_low;

              int the_clock = find_source(sender_string, packet_clock_id,
                                          (struct clock_source *)&shared_memory->clocks,
                                          (struct clock_private_info *)&clocks_private);
              if ((the_clock == -1) && ((buf[0] & 0xF) == Sync)) {
                the_clock = create_source(sender_string, packet_clock_id,
                                          (struct clock_source *)&shared_memory->clocks,
                                          (struct clock_private_info *)&clocks_private);
              }
              if (the_clock != -1) {
                switch (buf[0] & 0xF) {
                case Sync: { // if it's a sync
                  struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
                  // this is just to see if anything interesting comes in the SYNC package
                  // a non-zero origin timestamp
                  // or correction field would be interesting....
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

                  int discard_sync = 0;

                  // check if we should discard this SYNC
                  if (clocks_private[the_clock].current_stage != waiting_for_sync) {

                    // here, we have an unexpected SYNC. It could be because the
                    // previous transaction sequence failed for some reason
                    // But, if that is so, the SYNC will have a newer sequence number
                    // so, ignore it if it's a little older.

                    // If it seems a lot older in sequence number terms, then it might
                    // be the start of a completely new sequence, so if the
                    // difference is more than 40 (WAG), accept it

                    uint16_t new_sync_sequence_number = ntohs(msg->header.sequenceId);
                    int16_t sequence_number_difference =
                        (clocks_private[the_clock].sequence_number - new_sync_sequence_number);

                    if ((sequence_number_difference > 0) && (sequence_number_difference < 40))
                      discard_sync = 1;
                  }

                  if (discard_sync == 0) {

                    clocks_private[the_clock].sequence_number = ntohs(msg->header.sequenceId);
                    clocks_private[the_clock].t2 = reception_time;

                    // it turns out that we don't really need to send a Delay_Req
                    // as a Follow_Up message always comes through

                    // If we had hardware assisted network timing, then maybe
                    // Even then, AP2 devices don't seem to send an accurate
                    // Delay_Resp time -- it contains the same information is the Follow_Up

                    clocks_private[the_clock].current_stage = sync_seen;
                  }
                } break;

                case Follow_Up: {
                  struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
                  if ((clocks_private[the_clock].current_stage == sync_seen) &&
                      (clocks_private[the_clock].sequence_number ==
                       ntohs(msg->header.sequenceId))) {

                    uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
                    uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
                    uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
                    uint64_t preciseOriginTimestamp = seconds_hi;
                    preciseOriginTimestamp = preciseOriginTimestamp << 32;
                    preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
                    preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
                    preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;
                    // this result is called "t1" in the IEEE spec.
                    // we already have "t2" and it seems as if we can't generate "t3"
                    // and "t4", so use t1 - t2 as the clock-to-local offsets

                    clocks_private[the_clock].current_stage = waiting_for_sync;

                    // update the shared clock information
                    uint64_t offset = preciseOriginTimestamp - clocks_private[the_clock].t2;

                    int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
                    if (rc != 0)
                      warn("Can't acquire mutex to update a clock!");
                    shared_memory->clocks[the_clock].valid = 1;
                    shared_memory->clocks[the_clock].local_time = clocks_private[the_clock].t2;
                    shared_memory->clocks[the_clock].local_to_source_time_offset = offset;
                    rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
                    if (rc != 0)
                      warn("Can't release mutex after updating a clock!");

                  } else {
                    debug(3,
                          "Follow_Up %u expecting to be in state sync_seen (%u). Stage error -- "
                          "current state is %u, sequence %u. Ignoring it. %s",
                          ntohs(msg->header.sequenceId), sync_seen,
                          clocks_private[the_clock].current_stage,
                          clocks_private[the_clock].sequence_number,
                          &shared_memory->clocks[the_clock].ip);
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
      deactivate_old_sources(reception_time, (struct clock_source *)&shared_memory->clocks,
                             (struct clock_private_info *)&clocks_private);
    }
  }

  // here, close all the sockets...

  return 0;
}
