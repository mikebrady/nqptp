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

#include <arpa/inet.h> // inet_ntop
#include <stdio.h>     // fprint
#include <stdlib.h>    // malloc;
#include <string.h>    // memset

#include <errno.h>
#include <unistd.h> // close

#include <fcntl.h>      /* For O_* constants */
#include <sys/mman.h>   // for shared memory stuff
#include <sys/select.h> // for fd_set
#include <sys/stat.h>   // umask
#include <time.h>       // for timeval

#include <signal.h> // SIGTERM and stuff like that

#include <netdb.h>
#include <sys/socket.h>

#ifdef CONFIG_FOR_FREEBSD
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

// 8 samples per second

#define BUFLEN 4096 // Max length of buffer

sockets_open_bundle sockets_open_stuff;

typedef struct {
  uint64_t trigger_time;
  uint64_t (*task)(uint64_t nominal_call_time, void *private_data);
  void *private_data;
} timed_task_t;

#define TIMED_TASKS 1

timed_task_t timed_tasks[TIMED_TASKS];

/*
uint64_t sample_task(uint64_t call_time, __attribute__((unused)) void *private_data) {
  debug(1,"sample_task called.");
  uint64_t next_time = call_time;
  next_time = next_time + 1000000000;
  return next_time;
}
*/

int epoll_fd;

void goodbye(void) {
  // close any open sockets
  unsigned int i;
  for (i = 0; i < sockets_open_stuff.sockets_open; i++)
    close(sockets_open_stuff.sockets[i].number);

  // close off shared memory interface
  delete_clients();

  // close off new smi
  // mmap cleanup
  if (munmap(shared_memory, sizeof(struct shm_structure)) != 0) {
    debug(1, "error unmapping shared memory \"%s\": \"%s\".", NQPTP_INTERFACE_NAME,
          strerror(errno));
  }
  // shm_open cleanup
  if (shm_unlink(NQPTP_INTERFACE_NAME) == -1) {
    debug(1, "error unlinking shared memory \"%s\": \"%s\".", NQPTP_INTERFACE_NAME,
          strerror(errno));
  }

  if (shm_fd != -1)
    close(shm_fd);

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
          fprintf(stdout, "Version: %s. Shared Memory Interface Version: smi%u.\n",
                  git_version_string, NQPTP_SHM_STRUCTURES_VERSION);
        else
#endif

          fprintf(stdout, "Version: %s. Shared Memory Interface Version: smi%u.\n", VERSION,
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

#ifdef CONFIG_USE_GIT_VERSION_STRING
  if (git_version_string[0] != '\0')
    debug(1, "Version: %s, smi%u. Clock ID: \"%" PRIx64 "\".", git_version_string,
          NQPTP_SHM_STRUCTURES_VERSION, get_self_clock_id());
  else
#endif
    debug(1, "Version: %s, smi%u. Clock ID: \"%" PRIx64 "\".", VERSION,
          NQPTP_SHM_STRUCTURES_VERSION, get_self_clock_id());

  // debug(1, "size of a clock entry is %u bytes.", sizeof(clock_source_private_data));
  atexit(goodbye);

  sockets_open_stuff.sockets_open = 0;

  epoll_fd = -1;

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

  // open the SMI

  shm_fd = -1;

  mode_t oldumask = umask(0);
  shm_fd = shm_open(NQPTP_INTERFACE_NAME, O_RDWR | O_CREAT, 0644);
  if (shm_fd == -1) {
    die("cannot open shared memory \"%s\".", NQPTP_INTERFACE_NAME);
  }
  (void)umask(oldumask);

  if (ftruncate(shm_fd, sizeof(struct shm_structure)) == -1) {
    die("failed to set size of shared memory \"%s\".", NQPTP_INTERFACE_NAME);
  }

#ifdef CONFIG_FOR_FREEBSD
  shared_memory = (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure),
                                               PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
#endif

#ifdef CONFIG_FOR_LINUX
  shared_memory =
      (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                   MAP_LOCKED | MAP_SHARED, shm_fd, 0);
#endif

  if (shared_memory == (struct shm_structure *)-1) {
    die("failed to mmap shared memory \"%s\".", NQPTP_INTERFACE_NAME);
  }

  if (shm_fd == -1) {
    warn("error closing \"%s\" after mapping.", shm_fd);
  }

  // zero it
  memset(shared_memory, 0, sizeof(struct shm_structure));
  shared_memory->version = NQPTP_SHM_STRUCTURES_VERSION;

  ssize_t recv_len;

  char buf[BUFLEN];

  // open sockets 319 and 320

  open_sockets_at_port(NULL, 319, &sockets_open_stuff);
  open_sockets_at_port(NULL, 320, &sockets_open_stuff);
  open_sockets_at_port("localhost", NQPTP_CONTROL_PORT,
                       &sockets_open_stuff); // this for messages from the client

  // start the timed tasks
  uint64_t broadcasting_task(uint64_t call_time, void *private_data);

  timed_tasks[0].trigger_time = get_time_now() + 100000000; // start after 100 ms
  timed_tasks[0].private_data = (void *)&clocks_private;
  timed_tasks[0].task = broadcasting_task;

  // now, get down to business
  if (sockets_open_stuff.sockets_open > 0) {

    while (1) {
      fd_set readSockSet;
      struct timeval timeout;
      FD_ZERO(&readSockSet);
      int smax = -1;
      unsigned int s;
      for (s = 0; s < sockets_open_stuff.sockets_open; s++) {
        if (sockets_open_stuff.sockets[s].number > smax)
          smax = sockets_open_stuff.sockets[s].number;
        FD_SET(sockets_open_stuff.sockets[s].number, &readSockSet);
      }

      timeout.tv_sec = 0;
      timeout.tv_usec = 10000; // timeout after ten milliseconds
      int retval = select(smax + 1, &readSockSet, NULL, NULL, &timeout);
      uint64_t reception_time = get_time_now(); // use this if other methods fail
      if (retval > 0) {
        unsigned t;
        for (t = 0; t < sockets_open_stuff.sockets_open; t++) {
          int socket_number = sockets_open_stuff.sockets[t].number;
          if (FD_ISSET(socket_number, &readSockSet)) {

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
              // check if it's a control port message before checking for the length of the
              // message.
            } else if (receiver_port == NQPTP_CONTROL_PORT) {
              handle_control_port_messages(
                  buf, recv_len, (clock_source_private_data *)&clocks_private, reception_time);
            } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
              debug_print_buffer(2, buf, recv_len);

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

              if (sender_port == receiver_port) {

                char sender_string[256];
                memset(sender_string, 0, sizeof(sender_string));
                inet_ntop(connection_ip_family, sender_addr, sender_string, sizeof(sender_string));
                // now, find the record for this ip
                int the_clock = find_clock_source_record(
                    sender_string, (clock_source_private_data *)&clocks_private);
                // not sure about requiring a Sync before creating it...
                // if ((the_clock == -1) && ((buf[0] & 0xF) == Sync)) {
                /*
                if (the_clock == -1) {
                  the_clock = create_clock_source_record(
                      sender_string, (clock_source_private_data *)&clocks_private);
                }
                */
                if (the_clock != -1) {
                  clocks_private[the_clock].time_of_last_use =
                      reception_time; // for garbage collection
                  switch (buf[0] & 0xF) {
                  case Announce:
                    handle_announce(buf, recv_len, &clocks_private[the_clock], reception_time);
                    break;
                  case Follow_Up:
                    handle_follow_up(buf, recv_len, &clocks_private[the_clock], reception_time);
                    break;
                  case Sync:
                    handle_sync(buf, recv_len, &clocks_private[the_clock], reception_time);
                    break;
                  default:
                    debug_print_buffer(2, buf,
                                       recv_len); // unusual messages will have debug level 1.
                    break;
                  }
                } // otherwise, just forget it
              }
            }
          }
        }
      }
      // if (retval >= 0)
      //  manage_clock_sources(reception_time, (clock_source_private_data *)&clocks_private);
      int i;
      for (i = 0; i < TIMED_TASKS; i++) {
        if (timed_tasks[i].trigger_time != 0) {
          int64_t time_to_wait = timed_tasks[i].trigger_time - reception_time;
          if (time_to_wait <= 0) {
            timed_tasks[i].trigger_time =
                timed_tasks[i].task(reception_time, timed_tasks[i].private_data);
          }
        }
      }
    }
  }
  // should never get to here, unless no sockets were ever opened.
  return 0;
}

void send_awakening_announcement_sequence(const uint64_t clock_id, const char *clock_ip,
                                          const int ip_family, const uint8_t priority1,
                                          const uint8_t priority2) {
  struct ptp_announce_message *msg;
  size_t msg_length = sizeof(struct ptp_announce_message);
  msg = malloc(msg_length);
  memset((void *)msg, 0, msg_length);

  uint64_t my_clock_id = get_self_clock_id();
  msg->header.transportSpecificAndMessageID = 0x10 + Announce;
  msg->header.reservedAndVersionPTP = 0x02;
  msg->header.messageLength = htons(sizeof(struct ptp_announce_message));
  msg->header.flags = htons(0x0408);
  hcton64(my_clock_id, &msg->header.clockIdentity[0]);
  msg->header.sourcePortID = htons(32776);
  msg->header.controlField = 0x05;
  msg->header.logMessagePeriod = 0xFE;
  msg->announce.currentUtcOffset = htons(37);
  hcton64(my_clock_id, &msg->announce.grandmasterIdentity[0]);
  uint32_t my_clock_quality = 0xf8fe436a;
  msg->announce.grandmasterClockQuality = htonl(my_clock_quality);
  if (priority1 > 2) {
    msg->announce.grandmasterPriority1 =
        priority1 - 1; // make this announcement seem better than the clock we are about to ping
    msg->announce.grandmasterPriority2 = priority2;
  } else {
    warn("Cannot select a suitable priority for pinging clock %" PRIx64 " at %s.", clock_id,
         clock_ip);
    msg->announce.grandmasterPriority1 = 248;
    msg->announce.grandmasterPriority2 = 248;
  }
  msg->announce.timeSource = 160; // Internal Oscillator

  // get the socket for the correct port -- 320 -- and family -- IPv4 or IPv6 -- to send it
  // from.

  int s = 0;
  unsigned t;
  for (t = 0; t < sockets_open_stuff.sockets_open; t++) {
    if ((sockets_open_stuff.sockets[t].port == 320) &&
        (sockets_open_stuff.sockets[t].family == ip_family))
      s = sockets_open_stuff.sockets[t].number;
  }
  if (s == 0) {
    debug(1, "sending socket not found for clock %" PRIx64 " at %s, family %s.", clock_id, clock_ip,
          ip_family == AF_INET    ? "IPv4"
          : ip_family == AF_INET6 ? "IPv6"
                                  : "Unknown");
  } else {
    // debug(1, "Send message from socket %d.", s);

    const char *portname = "320";
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo *res = NULL;
    int err = getaddrinfo(clock_ip, portname, &hints, &res);
    if (err != 0) {
      debug(1, "failed to resolve remote socket address (err=%d)", err);
    } else {
      // here, we have the destination, so send it

      // debug_print_buffer(1, (char *)msg, msg_length);
      int ret = sendto(s, msg, msg_length, 0, res->ai_addr, res->ai_addrlen);
      if (ret == -1)
        debug(1, "result of sendto is %d.", ret);
      debug(2, "Send awaken Announce message to clock \"%" PRIx64 "\" at %s on %s.", clock_id,
            clock_ip, ip_family == AF_INET6 ? "IPv6" : "IPv4");

      if (priority1 < 254) {
        msg->announce.grandmasterPriority1 =
            priority1 + 1; // make this announcement seem worse than the clock we about to ping
      } else {
        warn("Cannot select a suitable priority for second ping of clock %" PRIx64 " at %s.",
             clock_id, clock_ip);
        msg->announce.grandmasterPriority1 = 250;
      }

      msg->announce.grandmasterPriority2 = priority2;
      usleep(150000);
      ret = sendto(s, msg, msg_length, 0, res->ai_addr, res->ai_addrlen);
      if (ret == -1)
        debug(1, "result of second sendto is %d.", ret);
      freeaddrinfo(res);
    }
  }
  free(msg);
}

uint64_t broadcasting_task(uint64_t call_time, __attribute__((unused)) void *private_data) {
  clock_source_private_data *clocks_private = (clock_source_private_data *)private_data;
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {

    /*
        int is_a_master = 0;
        int temp_client_id;

        for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++)
          if ((clocks_private->client_flags[temp_client_id] & (1 << clock_is_master)) != 0)
            is_a_master = 1;
        // only process it if it's a master somewhere...
        if ((is_a_master != 0) && (clocks_private[i].announcements_without_followups == 3)) {
    */
    if (clocks_private[i].announcements_without_followups == 3) {
      if (clocks_private[i].follow_up_number == 0) {
        debug(1,
              "Attempt to awaken a silent clock %" PRIx64
              ", index %u, at follow_up_number %u at IP %s.",
              clocks_private[i].clock_id, i, clocks_private[i].follow_up_number,
              clocks_private[i].ip);

        // send an Announce message to attempt to waken this silent PTP clock by
        // getting it to negotiate with an apparently better clock
        // that then immediately sends another Announce message indicating that it's inferior

        clocks_private[i].announcements_without_followups++; // set to 4 to indicate done/parked
        send_awakening_announcement_sequence(
            clocks_private[i].clock_id, clocks_private[i].ip, clocks_private[i].family,
            clocks_private[i].grandmasterPriority1, clocks_private[i].grandmasterPriority2);
      } else {
        debug(1,
              "Silent clock %" PRIx64
              " detected, index %u, at follow_up_number %u at IP %s. No attempt to awaken it.",
              clocks_private[i].clock_id, i, clocks_private[i].follow_up_number,
              clocks_private[i].ip);
      }
    }
  }

  /*
    uint64_t announce_interval = 1;
    announce_interval = announce_interval << (8 + aPTPinitialLogAnnounceInterval);
    announce_interval = announce_interval * 1000000000;
    announce_interval = announce_interval >> 8; // nanoseconds
    return call_time + announce_interval;
  */
  return call_time + 50000000;
}
