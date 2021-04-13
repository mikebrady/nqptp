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
#include "nqptp-ptp-definitions.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/types.h>

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

clock_source_private_data clocks_private[MAX_CLOCKS];

int find_clock_source_record(char *sender_string, clock_source *clocks_shared_info,
                             clock_source_private_data *clocks_private_info) {
  // return the index of the clock in the clock information arrays or -1
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if ((clocks_private_info[i].in_use != 0) &&
        (strcasecmp(sender_string, (const char *)&clocks_shared_info[i].ip) == 0))
      found = 1;
    else
      i++;
  }
  if (found == 1)
    response = i;
  return response;
}

int create_clock_source_record(char *sender_string, clock_source *clocks_shared_info,
                               clock_source_private_data *clocks_private_info, int use_lock) {
  // sometimes, the mutex will already be locked
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
    if (use_lock != 0) {
      if (pthread_mutex_lock(&shared_memory->shm_mutex) != 0)
        warn("Can't acquire mutex to activate a new  clock!");
    }
    memset(&clocks_shared_info[i], 0, sizeof(clock_source));
    strncpy((char *)&clocks_shared_info[i].ip, sender_string, FIELD_SIZEOF(clock_source, ip) - 1);
    if (use_lock != 0) {
      if (pthread_mutex_unlock(&shared_memory->shm_mutex) != 0)
        warn("Can't release mutex after activating a new clock!");
    }
    memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
    clocks_private_info[i].in_use = 1;
    clocks_private_info[i].t2 = 0;
    clocks_private_info[i].current_stage = waiting_for_sync;
    clocks_private_info[i].vacant_samples = MAX_TIMING_SAMPLES;
    debug(2, "activated source %d with clock_id %" PRIx64 " on ip: %s.", i,
          clocks_shared_info[i].clock_id, &clocks_shared_info[i].ip);
  } else {
    die("Clock tables full!");
  }
  return response;
}

void manage_clock_sources(uint64_t reception_time, clock_source *clocks_shared_info,
                          clock_source_private_data *clocks_private_info) {
  debug(3, "manage_clock_sources");
  int i;
  // do a garbage collect for clock records no longer in use
  for (i = 0; i < MAX_CLOCKS; i++) {
    // only if its in use and not a timing peer... don't need a mutex to check
    if ((clocks_private_info[i].in_use != 0) &&
        ((clocks_shared_info[i].flags & (1 << clock_is_a_timing_peer)) == 0)) {
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
        debug(2, "deactivated source %d with clock_id %" PRIx64 " on ip: %s.", i,
              clocks_shared_info[i].clock_id, &clocks_shared_info[i].ip);
        int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
        if (rc != 0)
          warn("Can't acquire mutex to deactivate a clock!");
        memset(&clocks_shared_info[i], 0, sizeof(clock_source));
        rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
        if (rc != 0)
          warn("Can't release mutex after deactivating a clock!");
        memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
      }
    }
  }
}

// check all the entries in the clock array and mark all those that
// belong to ourselves

void update_clock_self_identifications(clock_source *clocks_shared_info,
                                       clock_source_private_data *clocks_private_info) {
  // first, turn off all the self-id flags
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    clocks_private_info[i].is_one_of_ours = 0;
  }

  struct ifaddrs *ifap, *ifa;
  void *addr = NULL;
  short family;
  getifaddrs(&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    family = ifa->ifa_addr->sa_family;
#ifdef AF_INET6
    if (ifa->ifa_addr && family == AF_INET6) {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      addr = &(sa6->sin6_addr);
    }
#endif
    if (ifa->ifa_addr && family == AF_INET) {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)ifa->ifa_addr;
      addr = &(sa4->sin_addr);
    }
    char ip_string[64];
    memset(ip_string, 0, sizeof(ip_string));
    if (addr != NULL)
      inet_ntop(family, addr, ip_string, sizeof(ip_string));
    if (strlen(ip_string) != 0) {
      // now set the is_one_of_ours flag of any clock with this ip
      for (i = 0; i < MAX_CLOCKS; i++) {
        if (strcasecmp(ip_string, clocks_shared_info[i].ip) == 0) {
          debug(2, "found an entry for one of our clocks");
          clocks_private_info[i].is_one_of_ours = 1;
        }
      }
    }
  }
  freeifaddrs(ifap);
}
