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

#include "nqptp-clock-sources.h"
#include "debug.h"
#include "general-utilities.h"
#include "nqptp-ptp-definitions.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h> // for ftruncate and others
#include <unistd.h>    // for ftruncate and others

#include <fcntl.h>      /* For O_* constants */
#include <sys/mman.h>   // for shared memory stuff
#include <sys/select.h> // for fd_set
#include <sys/stat.h>   // umask

#ifdef CONFIG_FOR_FREEBSD
#include <netinet/in.h>
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

clock_source_private_data clocks_private[MAX_CLOCKS];
client_record clients[MAX_CLIENTS];

int find_client_id(char *client_shared_memory_interface_name) {
  int response = -1; // signify not found
  if (client_shared_memory_interface_name != NULL) {
    int i = 0;
    // first, see if yu can find it anywhere
    while ((response == -1) && (i < MAX_CLIENTS)) {
      if (strcmp(clients[i].shm_interface_name, client_shared_memory_interface_name) == 0)
        response = i;
      else
        i++;
    }
  }
  return response;
}

const char *get_client_name(int client_id) {
  if ((client_id >= 0) && (client_id < MAX_CLIENTS)) {
    return clients[client_id].shm_interface_name;
  } else {
    return "";
  }
}

int get_client_id(char *client_shared_memory_interface_name) {
  int response = -1; // signify not found
  if (client_shared_memory_interface_name != NULL) {
    int i = 0;
    // first, see if yu can find it anywhere
    while ((response == -1) && (i < MAX_CLIENTS)) {
      if (strcmp(clients[i].shm_interface_name, client_shared_memory_interface_name) == 0)
        response = i;
      else
        i++;
    }

    if (response == -1) { // no match, so create one
      i = 0;
      while ((response == -1) && (i < MAX_CLIENTS)) {
        if (clients[i].shm_interface_name[0] == '\0')
          response = i;
        else
          i++;
      }
      if (response != -1) {
        pthread_mutexattr_t shared;
        int err;
        strncpy(clients[i].shm_interface_name, client_shared_memory_interface_name,
                sizeof(clients[i].shm_interface_name));
        // creat the named smi interface

        // open a shared memory interface.
        clients[i].shm_fd = -1;

        mode_t oldumask = umask(0);
        clients[i].shm_fd = shm_open(client_shared_memory_interface_name, O_RDWR | O_CREAT, 0666);
        if (clients[i].shm_fd == -1) {
          die("cannot open shared memory \"%s\".", client_shared_memory_interface_name);
        }
        (void)umask(oldumask);

        if (ftruncate(clients[i].shm_fd, sizeof(struct shm_structure)) == -1) {
          die("failed to set size of shared memory \"%s\".", client_shared_memory_interface_name);
        }

#ifdef CONFIG_FOR_FREEBSD
        clients[i].shared_memory =
            (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                         MAP_SHARED, clients[i].shm_fd, 0);
#endif

#ifdef CONFIG_FOR_LINUX
        clients[i].shared_memory =
            (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                         MAP_LOCKED | MAP_SHARED, clients[i].shm_fd, 0);
#endif

        if (clients[i].shared_memory == (struct shm_structure *)-1) {
          die("failed to mmap shared memory \"%s\".", client_shared_memory_interface_name);
        }

        if ((close(clients[i].shm_fd) == -1)) {
          warn("error closing \"%s\" after mapping.", client_shared_memory_interface_name);
        }

        // zero it
        memset(clients[i].shared_memory, 0, sizeof(struct shm_structure));
        clients[i].shared_memory->version = NQPTP_SHM_STRUCTURES_VERSION;

        /*create mutex attr */
        err = pthread_mutexattr_init(&shared);
        if (err != 0) {
          die("mutex attribute initialization failed - %s.", strerror(errno));
        }
        pthread_mutexattr_setpshared(&shared, 1);
        /*create a mutex */
        err = pthread_mutex_init((pthread_mutex_t *)&clients[i].shared_memory->shm_mutex, &shared);
        if (err != 0) {
          die("mutex initialization failed - %s.", strerror(errno));
        }

        err = pthread_mutexattr_destroy(&shared);
        if (err != 0) {
          die("mutex attribute destruction failed - %s.", strerror(errno));
        }

        for (i = 0; i < MAX_CLOCKS; i++) {
          clocks_private[i].client_flags[response] =
              0; // turn off all client flags in every clock for this client
        }
      } else {
        debug(1, "could not create a client record for client \"%s\".",
              client_shared_memory_interface_name);
      }
    }
  } else {
    debug(1, "no client_shared_memory_interface_name");
  }
  return response;
}

int delete_client(int client_id) {
  int response = 0; // okay unless something happens
  if (clients[client_id].shm_interface_name[0] != '\0') {
    if (clients[client_id].shared_memory != NULL) {
      // mmap cleanup
      if (munmap(clients[client_id].shared_memory, sizeof(struct shm_structure)) != 0) {
        debug(1, "error unmapping shared memory");
        response = -1;
      }
      // shm_open cleanup
      if (shm_unlink(clients[client_id].shm_interface_name) == -1) {
        debug(1, "error unlinking shared memory \"%s\"", clients[client_id].shm_interface_name);
        response = -1;
      }
    }
    clients[client_id].shm_interface_name[0] = '\0'; // remove the name to signify it's vacant
  }
  return response;
}

int delete_clients() {
  int response = 0; // okay unless something happens
  int i;
  for (i = 0; i < MAX_CLIENTS; i++)
    if (delete_client(i) != 0)
      response = -1;
  return response;
}

int find_clock_source_record(char *sender_string, clock_source_private_data *clocks_private_info) {
  // return the index of the clock in the clock information arrays or -1
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if (((clocks_private_info[i].flags & (1 << clock_is_in_use)) != 0) &&
        (strcasecmp(sender_string, (const char *)&clocks_private_info[i].ip) == 0))
      found = 1;
    else
      i++;
  }
  if (found == 1)
    response = i;
  return response;
}

int create_clock_source_record(char *sender_string,
                               clock_source_private_data *clocks_private_info) {
  // return the index of a clock entry in the clock information arrays or -1 if full
  // initialise the entries in the shared and private arrays
  int response = -1;
  int i = 0;
  int found = 0; // trying to find an unused entry
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if ((clocks_private_info[i].flags & (1 << clock_is_in_use)) == 0)
      found = 1;
    else
      i++;
  }

  if (found == 1) {
    int family = 0;

    // check its ipv4/6 family -- derived from https://stackoverflow.com/a/3736377, with thanks.
    struct addrinfo hint, *res = NULL;
    memset(&hint, '\0', sizeof hint);
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(sender_string, NULL, &hint, &res) == 0) {
      family = res->ai_family;
      freeaddrinfo(res);
      response = i;
      memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
      strncpy((char *)&clocks_private_info[i].ip, sender_string,
              FIELD_SIZEOF(clock_source_private_data, ip) - 1);
      clocks_private_info[i].family = family;
      clocks_private_info[i].flags |= (1 << clock_is_in_use);
      debug(2, "create record for ip: %s, family: %s.", &clocks_private_info[i].ip,
            clocks_private_info[i].family == AF_INET6 ? "IPv6" : "IPv4");
    } else {
      debug(1, "cannot getaddrinfo for ip: %s.", &clocks_private_info[i].ip);
    }
  } else {
    debug(1, "Clock tables full!");
  }
  return response;
}

void manage_clock_sources(uint64_t reception_time, clock_source_private_data *clocks_private_info) {
  debug(3, "manage_clock_sources");
  int i;

  // do a garbage collect for clock records no longer in use
  for (i = 0; i < MAX_CLOCKS; i++) {
    // only if its in use and not a timing peer... don't need a mutex to check
    // TODO -- check all clients to see if it's in use
    if ((clocks_private_info[i].flags & (1 << clock_is_in_use)) != 0) {
      int clock_is_a_timing_peer_somewhere = 0;
      int temp_client_id;
      for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
        if ((clocks_private_info[i].client_flags[temp_client_id] & (1 << clock_is_a_timing_peer)) !=
            0) {
          clock_is_a_timing_peer_somewhere = 1;
        }
      }
      if (clock_is_a_timing_peer_somewhere == 0) {
        int64_t time_since_last_use = reception_time - clocks_private_info[i].time_of_last_use;
        // using a sync timeout to determine when to drop the record...
        // the following give the sync receipt time in whole seconds
        // depending on the aPTPinitialLogSyncInterval and the aPTPsyncReceiptTimeout
        int64_t syncTimeout = (1 << (32 + aPTPinitialLogSyncInterval));
        syncTimeout = syncTimeout * aPTPsyncReceiptTimeout;
        syncTimeout = syncTimeout >> 32;
        // seconds to nanoseconds
        syncTimeout = syncTimeout * 1000000000;
        if (time_since_last_use > syncTimeout) {
          uint32_t old_flags = clocks_private_info[i].flags;
          debug(2, "delete record for: %s.", &clocks_private_info[i].ip);
          memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
          if (old_flags != 0) {
            update_master(0); // TODO -- won't be needed
          } else {
            debug_log_nqptp_status(2);
          }
        }
      }
    }
  }
}

// check all the entries in the clock array and mark all those that
// belong to ourselves

void update_clock_self_identifications(clock_source_private_data *clocks_private_info) {
  // first, turn off all the self-id flags
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    clocks_private_info[i].flags &= ~(1 << clock_is_one_of_ours);
  }

  struct ifaddrs *ifap, *ifa;
  void *addr = NULL;
  short family;
  int response = getifaddrs(&ifap);
  if (response == 0) {
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      struct sockaddr *my_ifa_addr = ifa->ifa_addr;
      if (my_ifa_addr) {
        family = my_ifa_addr->sa_family;
#ifdef AF_INET6
        if (family == AF_INET6) {
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)my_ifa_addr;
          addr = &(sa6->sin6_addr);
        }
#endif
        if (family == AF_INET) {
          struct sockaddr_in *sa4 = (struct sockaddr_in *)my_ifa_addr;
          addr = &(sa4->sin_addr);
        }
        char ip_string[64];
        memset(ip_string, 0, sizeof(ip_string));
        if (addr != NULL)
          inet_ntop(family, addr, ip_string, sizeof(ip_string));
        if (strlen(ip_string) != 0) {
          // now set the clock_is_one_of_ours flag of any clock with this ip
          for (i = 0; i < MAX_CLOCKS; i++) {
            if (strcasecmp(ip_string, clocks_private_info[i].ip) == 0) {
              debug(2, "found an entry for one of our clocks");
              clocks_private_info[i].flags |= (1 << clock_is_one_of_ours);
            }
          }
        }
      } else {
        debug(1, "NULL ifa->ifa_addr. Probably harmless.");
      }
    }
    freeifaddrs(ifap);
  } else {
    debug(1, "getifaddrs error - %s.", strerror(errno));
  }
}

void debug_log_nqptp_status(__attribute__((unused)) int level) {
  /*
    int records_in_use = 0;
    int i;
    for (i = 0; i < MAX_CLOCKS; i++)
      if ((clocks_private[i].flags & (1 << clock_is_in_use)) != 0)
        records_in_use++;
    debug(level, "");
    if (records_in_use > 0) {
      debug(level, "Current NQPTP Status:");
      uint32_t peer_mask = (1 << clock_is_a_timing_peer);
      uint32_t peer_clock_mask = peer_mask | (1 << clock_is_valid);
      uint32_t peer_master_mask = peer_clock_mask | (1 << clock_is_master);
      uint32_t peer_becoming_master_mask = peer_clock_mask | (1 << clock_is_becoming_master);
      uint32_t non_peer_clock_mask = (1 << clock_is_valid);
      uint32_t non_peer_master_mask = non_peer_clock_mask | (1 << clock_is_master);
      for (i = 0; i < MAX_CLOCKS; i++) {
        if ((clocks_private[i].flags & (1 << clock_is_in_use)) != 0) {
          if ((clocks_private[i].flags & peer_master_mask) == peer_master_mask) {
            debug(level, "  Peer Master:            %" PRIx64 "  %s.", clocks_private[i].clock_id,
                  clocks_private[i].ip);
          } else if ((clocks_private[i].flags & peer_becoming_master_mask) ==
                     peer_becoming_master_mask) {
            debug(level, "  Peer Becoming Master:   %" PRIx64 "  %s.", clocks_private[i].clock_id,
                  clocks_private[i].ip);
          } else if ((clocks_private[i].flags & peer_clock_mask) == peer_clock_mask) {
            debug(level, "  Peer Clock:             %" PRIx64 "  %s.", clocks_private[i].clock_id,
                  clocks_private[i].ip);
          } else if ((clocks_private[i].flags & peer_mask) == peer_mask) {
            debug(level, "  Peer:                                     %s.", clocks_private[i].ip);
          } else if ((clocks_private[i].flags & non_peer_master_mask) == non_peer_master_mask) {
            debug(level, "  Non Peer Master:        %" PRIx64 "  %s.", clocks_private[i].clock_id,
                  clocks_private[i].ip);
          } else if ((clocks_private[i].flags & non_peer_clock_mask) == non_peer_clock_mask) {
            debug(level, "  Non Peer Clock:         %16" PRIx64 "  %s.", clocks_private[i].clock_id,
                  clocks_private[i].ip);
          } else {
            debug(level, "  Non Peer Record:                          %s.", clocks_private[i].ip);
          }
        }
      }
    } else {
      debug(level, "Current NQPTP Status: no records in use.");
    }
  */
}

int uint32_cmp(uint32_t a, uint32_t b, const char *cause) {
  // returns -1 if a is less than b, 0 if a = b, +1 if a is greater than b
  if (a == b) {
    return 0;
  } else {
    debug(2, "Best Master Clock algorithm deciding factor: %s. Values: %u, %u.", cause, a, b);
    if (a < b)
      return -1;
    else
      return 1;
  }
}

int uint64_cmp(uint64_t a, uint64_t b, const char *cause) {
  // returns -1 if a is less than b, 0 if a = b, +1 if a is greater than b
  if (a == b) {
    return 0;
  } else {
    debug(2, "Best Master Clock algorithm deciding factor: %s. Values: %" PRIx64 ", %" PRIx64 ".",
          cause, a, b);
    if (a < b)
      return -1;
    else
      return 1;
  }
}

void update_master(int client_id) {

  // This implements the IEEE 1588-2008 best master clock algorithm.

  // However, since nqptp is not a ptp clock, some of it doesn't apply.
  // Specifically, the Identity of Receiver stuff doesn't apply, since the
  // program is merely monitoring Announce message data and isn't a PTP clock itself
  // and thus does not have any kind or receiver identity itself.

  // Clock information coming from the same clock over IPv4 and IPv6 should have different
  // port numbers.

  // Figure 28 can be therefore be simplified considerably:

  // Since nqptp can not be a receiver, and since nqptp can not originate a clock
  // (and anyway nqptp filters out packets coming from self)
  // we can do a single comparison of stepsRemoved and pick the shorter, if any.

  // Figure 28 reduces to checking steps removed and then, if necessary, checking identities.
  // If we see two identical sets of information, it is an error,
  // but we leave things as they are.
  int old_master = -1;
  // find the current master clock if there is one and turn off all mastership
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clocks_private[i].client_flags[client_id] & (1 << clock_is_master)) != 0)
      if (old_master == -1)
        old_master = i;                                                   // find old master
    clocks_private[i].client_flags[client_id] &= ~(1 << clock_is_master); // turn them all off
    clocks_private[i].client_flags[client_id] &=
        ~(1 << clock_is_becoming_master); // turn them all off
  }

  int best_so_far = -1;
  int timing_peer_count = 0;
  //  uint32_t clock_specific_acceptance_mask = (1 << clock_is_qualified) | (1 << clock_is_valid);
  uint32_t clock_specific_acceptance_mask = (1 << clock_is_qualified);
  uint32_t client_specific_acceptance_mask = (1 << clock_is_a_timing_peer);
  for (i = 0; i < MAX_CLOCKS; i++) {
    if (((clocks_private[i].flags & clock_specific_acceptance_mask) ==
         clock_specific_acceptance_mask) &&
        ((clocks_private[i].client_flags[client_id] & client_specific_acceptance_mask) ==
         client_specific_acceptance_mask)) {
      // found a possible clock candidate
      timing_peer_count++;
      int outcome;
      if (best_so_far == -1) {
        best_so_far = i;
      } else {
        // Do the data set comparison detailed in Figure 27 and Figure 28 on pp89-90
        if (clocks_private[i].grandmasterIdentity ==
            clocks_private[best_so_far].grandmasterIdentity) {
          // Do the relevant part of Figure 28:
          outcome = uint32_cmp(clocks_private[i].stepsRemoved,
                               clocks_private[best_so_far].stepsRemoved, "steps removed");
          // we need to check the portIdentify, which is the clock_id and the clock_port_number
          if (outcome == 0)
            outcome = uint64_cmp(clocks_private[i].clock_id, clocks_private[best_so_far].clock_id,
                                 "clock id");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].clock_port_number,
                           clocks_private[best_so_far].clock_port_number, "clock port number");
          if (outcome == 0) {
            debug(1,
                  "Best Master Clock algorithm: two separate but identical potential clock "
                  "masters: %" PRIx64 ".",
                  clocks_private[best_so_far].clock_id);
          }

        } else {
          outcome =
              uint32_cmp(clocks_private[i].grandmasterPriority1,
                         clocks_private[best_so_far].grandmasterPriority1, "grandmasterPriority1");
          if (outcome == 0)
            outcome = uint32_cmp(clocks_private[i].grandmasterClass,
                                 clocks_private[best_so_far].grandmasterClass, "grandmasterClass");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].grandmasterAccuracy,
                           clocks_private[best_so_far].grandmasterAccuracy, "grandmasterAccuracy");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].grandmasterVariance,
                           clocks_private[best_so_far].grandmasterVariance, "grandmasterVariance");
          if (outcome == 0)
            outcome = uint32_cmp(clocks_private[i].grandmasterPriority2,
                                 clocks_private[best_so_far].grandmasterPriority2,
                                 "grandmasterPriority2");
          if (outcome == 0)
            // this can't fail, as it's a condition of entering this section that they are different
            outcome =
                uint64_cmp(clocks_private[i].grandmasterIdentity,
                           clocks_private[best_so_far].grandmasterIdentity, "grandmasterIdentity");
        }
        if (outcome == -1)
          best_so_far = i;
      }
    }
  }
  if (best_so_far == -1) {
    // no master clock
    // if (old_master != -1) {
    // but there was a master clock, so remove it
    debug(1, "Remove master clock information from interface %s.", get_client_name(client_id));
    update_master_clock_info(client_id, 0, NULL, 0, 0, 0);
    //}
    if (timing_peer_count == 0)
      debug(2, "no valid qualified clocks ");
    else
      debug(1, "no master clock!");
  } else {
    // we found a master clock

    if (old_master != best_so_far) {
      // if the master is a new one
      // now, if it's already a master somewhere, it doesn't need to resync
      int clock_is_a_master_somewhere = 0;
      int temp_client_id;
      for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
        if ((clocks_private[best_so_far].client_flags[temp_client_id] & (1 << clock_is_master)) !=
            0) {
          clock_is_a_master_somewhere = 1;
        }
      }
      if (clock_is_a_master_somewhere == 0) {
        clocks_private[best_so_far].client_flags[client_id] |= (1 << clock_is_becoming_master);
        clocks_private[best_so_far].last_sync_time = 0; // declare it was never synced before

      } else {
        clocks_private[best_so_far].client_flags[client_id] |= (1 << clock_is_master);
      }
    } else {
      // if it's the same one as before
      clocks_private[best_so_far].client_flags[client_id] |= (1 << clock_is_master);
    }
  }
  debug_log_nqptp_status(2);
}

void update_master_clock_info(int client_id, uint64_t master_clock_id, const char *ip,
                              uint64_t local_time, uint64_t local_to_master_offset,
                              uint64_t mastership_start_time) {
  if (clients[client_id].shm_interface_name[0] != '\0') {
    // debug(1,"update_master_clock_info start");
    if (clients[client_id].shared_memory->master_clock_id != master_clock_id)
      debug_log_nqptp_status(1);
    int rc = pthread_mutex_lock(&clients[client_id].shared_memory->shm_mutex);
    if (rc != 0)
      warn("Can't acquire mutex to update master clock!");
    clients[client_id].shared_memory->master_clock_id = master_clock_id;
    if (ip != NULL) {
      strncpy((char *)&clients[client_id].shared_memory->master_clock_ip, ip,
              FIELD_SIZEOF(struct shm_structure, master_clock_ip) - 1);
      clients[client_id].shared_memory->master_clock_start_time = mastership_start_time;
      clients[client_id].shared_memory->local_time = local_time;
      clients[client_id].shared_memory->local_to_master_time_offset = local_to_master_offset;
    } else {
      clients[client_id].shared_memory->master_clock_ip[0] = '\0';
      clients[client_id].shared_memory->master_clock_start_time = 0;
      clients[client_id].shared_memory->local_time = 0;
      clients[client_id].shared_memory->local_to_master_time_offset = 0;
    }
    rc = pthread_mutex_unlock(&clients[client_id].shared_memory->shm_mutex);
    if (rc != 0)
      warn("Can't release mutex after updating master clock!");
    // debug(1,"update_master_clock_info done");
  }
}
