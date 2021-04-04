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

#include <string.h>
#include "nqptp-clock-sources.h"
#include "debug.h"

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#endif

int find_clock_source_record(char *sender_string, uint64_t packet_clock_id,
                clock_source *clocks_shared_info,
                clock_source_private_data *clocks_private_info) {
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

int create_clock_source_record(char *sender_string, uint64_t packet_clock_id,
                  clock_source *clocks_shared_info,
                  clock_source_private_data *clocks_private_info) {
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
    memset(&clocks_shared_info[i], 0, sizeof(clock_source));
    strncpy((char *)&clocks_shared_info[i].ip, sender_string, FIELD_SIZEOF(clock_source,ip) - 1);
    clocks_shared_info[i].clock_id = packet_clock_id;
    rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
    if (rc != 0)
      warn("Can't release mutex after activating a new clock!");

    memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
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

void manage_clock_sources(uint64_t reception_time, clock_source *clocks_shared_info,
                            clock_source_private_data *clocks_private_info) {
  debug(3, "manage_clock_sources");
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
        memset(&clocks_shared_info[i], 0, sizeof(clock_source));
        rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
        if (rc != 0)
          warn("Can't release mutex after deactivating a clock!");
        memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
      }
    }
  }
}

