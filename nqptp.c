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

#include "nqptp.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-clock-sources.h"
#include "nqptp-utilities.h"
#include "general-utilities.h"
#include "debug.h"

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

// 8 samples per second

#define BUFLEN 4096 // Max length of buffer
#define MAX_OPEN_SOCKETS 32 // up to 32 sockets open on ports 319 and 320

struct socket_info {
  int number;
  uint16_t port;
};

clock_source_private_data clocks_private[MAX_CLOCKS];

struct socket_info sockets[MAX_OPEN_SOCKETS];
unsigned int sockets_open =
    0; // also doubles as where to put next one, as sockets are never closed.
struct shm_structure *shared_memory = NULL; // this is where public clock info is available
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

              int the_clock = find_clock_source_record(sender_string, packet_clock_id,
                                          (clock_source *)&shared_memory->clocks,
                                          (clock_source_private_data *)&clocks_private);
              if ((the_clock == -1) && ((buf[0] & 0xF) == Sync)) {
                the_clock = create_clock_source_record(sender_string, packet_clock_id,
                                          (clock_source *)&shared_memory->clocks,
                                          (clock_source_private_data *)&clocks_private);
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
      manage_clock_sources(reception_time, (clock_source *)&shared_memory->clocks,
                             (clock_source_private_data *)&clocks_private);
    }
  }

  // here, close all the sockets...

  return 0;
}
