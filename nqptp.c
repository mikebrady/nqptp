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
#include "nqptp.h"
#include "config.h"
#include "debug.h"
#include "general-utilities.h"
#include "nqptp-clock-sources.h"
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"

#ifdef CONFIG_USE_GIT_VERSION_STRING
#include "gitversion.h"
#endif

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

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

// 8 samples per second

#define BUFLEN 4096    // Max length of buffer
#define MAX_EVENTS 128 // For epoll

sockets_open_bundle sockets_open_stuff;

int master_clock_index = -1;

struct shm_structure *shared_memory = NULL; // this is where public clock info is available
int epoll_fd;

void update_master_clock_info(uint64_t master_clock_id, const char *ip, uint64_t local_time,
                              uint64_t local_to_master_offset) {
  if (shared_memory->master_clock_id != master_clock_id)
    debug(1, "Master clock is: %" PRIx64 ".", master_clock_id);
  int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
  if (rc != 0)
    warn("Can't acquire mutex to update master clock!");
  if (shared_memory->master_clock_id != master_clock_id) {
    shared_memory->master_clock_id = master_clock_id;
    shared_memory->master_clock_start_time = local_time;
  }
  if (ip != NULL)
    strncpy((char *)&shared_memory->master_clock_ip, ip,
            FIELD_SIZEOF(struct shm_structure, master_clock_ip) - 1);
  else
    shared_memory->master_clock_ip[0] = '\0';
  shared_memory->local_time = local_time;
  shared_memory->local_to_master_time_offset = local_to_master_offset;
  rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
  if (rc != 0)
    warn("Can't release mutex after updating master clock!");
}

void goodbye(void) {
  // close any open sockets
  unsigned int i;
  for (i = 0; i < sockets_open_stuff.sockets_open; i++)
    close(sockets_open_stuff.sockets[i].number);
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

int main(int argc, char **argv) {

  int debug_level = 0;
  int i;
  for (i = 1; i < argc; ++i) {
    if (argv[i][0] == '-') {
      if (strcmp(argv[i] + 1, "V") == 0) {
#ifdef CONFIG_USE_GIT_VERSION_STRING
        if (git_version_string[0] != '\0')
          fprintf(stdout, "Version: %s. Shared Memory Interface Version: %u.\n", git_version_string,
                  NQPTP_SHM_STRUCTURES_VERSION);
        else
#endif

          fprintf(stdout, "Version: %s. Shared Memory Interface Version: %u.\n", VERSION,
                  NQPTP_SHM_STRUCTURES_VERSION);
        exit(EXIT_SUCCESS);
      } else if (strcmp(argv[i] + 1, "vvv") == 0) {
        debug_level = 3;
      } else if (strcmp(argv[i] + 1, "vv") == 0) {
        debug_level = 2;
      } else if (strcmp(argv[i] + 1, "v") == 0) {
        debug_level = 1;
      } else if (strcmp(argv[i] + 1, "h") == 0) {
        fprintf(stdout, "    -V     print version,\n"
                        "    -v     verbose log,\n"
                        "    -vv    more verbose log,\n"
                        "    -vvv   very verbose log,\n"
                        "    -h     this help text.\n");
        exit(EXIT_SUCCESS);
      } else {
        fprintf(stdout, "%s -- unknown option. Program terminated.\n", argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }

  debug_init(debug_level, 0, 1, 1);
  debug(1, "startup");
  atexit(goodbye);

  sockets_open_stuff.sockets_open = 0;

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

  // open sockets 319 and 320

  open_sockets_at_port(319, &sockets_open_stuff);
  open_sockets_at_port(320, &sockets_open_stuff);
  open_sockets_at_port(NQPTP_CONTROL_PORT,
                       &sockets_open_stuff); // this for messages from the client

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

  // now, get down to business
  if (sockets_open_stuff.sockets_open > 0) {

    struct epoll_event event;
    int epoll_fd = epoll_create(32);

    if (epoll_fd == -1)
      die("Failed to create epoll file descriptor\n");

    unsigned int ep;
    for (ep = 0; ep < sockets_open_stuff.sockets_open; ep++) {
      // if (sockets[s].number > smax)
      // smax = sockets[s].number;
      event.events = EPOLLIN;
      event.data.fd = sockets_open_stuff.sockets[ep].number;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockets_open_stuff.sockets[ep].number, &event) != 0)
        die("failed to add socket %d to epoll", sockets_open_stuff.sockets[ep].number);
      else
        debug(3, "add socket %d to epoll", sockets_open_stuff.sockets[ep].number);
    }

    while (1) {

      struct epoll_event events[MAX_EVENTS];
      // the timeout is in milliseconds
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

          uint16_t receiver_port = 0;
          // int msgsize = recv(udpsocket_fd, &msg_buffer, 4, 0);
          recv_len = recvmsg(socket_number, &msg, MSG_DONTWAIT);

          if (recv_len != -1) {
            // get the receiver port
            unsigned int jp;
            for (jp = 0; jp < sockets_open_stuff.sockets_open; jp++) {
              if (socket_number == sockets_open_stuff.sockets[jp].number)
                receiver_port = sockets_open_stuff.sockets[jp].port;
            }
          }
          if (recv_len == -1) {
            if (errno == EAGAIN) {
              usleep(1000); // this can happen, it seems...
            } else {
              debug(1, "recvmsg() error %d", errno);
            }
            // check if it's a control port message before checking for the length of the message.
          } else if (receiver_port == NQPTP_CONTROL_PORT) {
            handle_control_port_messages(buf, recv_len,
                                         (clock_source_private_data *)&clocks_private);
          } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
            debug_print_buffer(2, buf, recv_len);
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

            //            if ((sender_port == receiver_port) && (connection_ip_family == AF_INET)) {
            if (sender_port == receiver_port) {

              char sender_string[256];
              memset(sender_string, 0, sizeof(sender_string));
              inet_ntop(connection_ip_family, sender_addr, sender_string, sizeof(sender_string));
              // now, find or create a record for this ip
              int the_clock = find_clock_source_record(
                  sender_string, (clock_source_private_data *)&clocks_private);
              // not sure about requiring a Sync before creating it...
              if ((the_clock == -1) && ((buf[0] & 0xF) == Sync)) {
                the_clock = create_clock_source_record(
                    sender_string, (clock_source_private_data *)&clocks_private);
              }
              if (the_clock != -1) {
                clocks_private[the_clock].time_of_last_use =
                    reception_time; // for garbage collection
                switch (buf[0] & 0xF) {
                case Announce:
                  // needed to reject messages coming from self
                  update_clock_self_identifications((clock_source_private_data *)&clocks_private);
                  handle_announce(buf, recv_len, &clocks_private[the_clock], reception_time);
                  break;
                case Follow_Up: {
                  handle_follow_up(buf, recv_len, &clocks_private[the_clock], reception_time);
                } break;
                default:
                  debug_print_buffer(2, buf, recv_len); // unusual messages will have debug level 1.
                  break;
                }
              }
            }
          }
        }
      }
      manage_clock_sources(reception_time, (clock_source_private_data *)&clocks_private);
    }
  }

  // here, close all the sockets...

  return 0;
}
