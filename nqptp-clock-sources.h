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

#ifndef NQPTP_CLOCK_SOURCES_H
#define NQPTP_CLOCK_SOURCES_H

#include "nqptp.h"

// transaction tracking
enum stage {
  waiting_for_sync,
  sync_seen,
};

#define MAX_TIMING_SAMPLES 480
typedef struct {
  uint64_t local, local_to_remote_offset;
} timing_samples;

// private information -- not for putting in shared memory -- about each clock source
typedef struct {
  uint16_t sequence_number;
  uint16_t in_use;
  enum stage current_stage;
  uint64_t t2, previous_offset, previous_estimated_offset;
  // for garbage collection
  uint64_t time_of_last_use; // will be taken out of use if not used for a while and not in the
                             // timing peer group
  // (A member of the timing peer group could appear and disappear)
  // for Announce Qualification
  uint64_t announce_times[4]; // we'll check qualification and currency using these
  int is_one_of_ours;         // true if it is one of our own clocks
  timing_samples samples[MAX_TIMING_SAMPLES];
  int vacant_samples; // the number of elements in the timing_samples array that are not yet used
  int next_sample_goes_here; // point to where in the timing samples array the next entries should
                             // go
} clock_source_private_data;

int find_clock_source_record(char *sender_string, clock_source *clocks_shared_info,
                             clock_source_private_data *clocks_private_info);

int create_clock_source_record(char *sender_string, clock_source *clocks_shared_info,
                               clock_source_private_data *clocks_private_info, int use_lock);

void update_clock_self_identifications(clock_source *clocks_shared_info,
                                       clock_source_private_data *clocks_private_info);

void manage_clock_sources(uint64_t reception_time, clock_source *clocks_shared_info,
                          clock_source_private_data *clocks_private_info);

#endif
