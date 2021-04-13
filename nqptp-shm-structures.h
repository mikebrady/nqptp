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

#ifndef NQPTP_SHM_STRUCTURES_H
#define NQPTP_SHM_STRUCTURES_H

#define STORAGE_ID "/nqptp"
#define MAX_CLOCKS 32
#define NQPTP_SHM_STRUCTURES_VERSION 2
#define NQPTP_CONTROL_PORT 9000

// the control port will accept a packet with the first letter being:
// "N" or "U" followed by a space and then a space-delimited
// list of ip numbers, either IPv4 or IPv6
// the whole not to exceed 4096 characters in total

#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>

// most of this will probably become private when
// the master clock selection stuff works automatically

typedef enum {
  clock_is_valid,
  clock_is_a_timing_peer,
  clock_is_qualified,
  clock_is_master
} clock_flags;

typedef enum {
  new_timing_peer_list = 'N', // followed by a (possibly empty) space-separated list of IPs
  update_timing_peer_list = 'U'
} control_port_command;

typedef struct {
  char ip[64]; // 64 is nicely aligned and bigger than INET6_ADDRSTRLEN (46)
  uint64_t clock_id;
  uint64_t local_time;                  // the local time when the offset was calculated
  uint64_t local_to_source_time_offset; // add this to the local time to get source time
  uint32_t flags;
} clock_source;

struct shm_structure {
  pthread_mutex_t shm_mutex;    // for safely accessing the structure
  uint16_t size_of_clock_array; // deprecated -- check this is equal to MAX_SHARED_CLOCKS
  uint16_t version;             // deprecated -- check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint32_t flags;               // unused
  uint64_t local_time;          // the time when the offset was calculated
  uint64_t local_to_ptp_time_offset; // add this to the local time to get PTP time
  uint64_t clock_id;    // for information only
  clock_source clocks[MAX_CLOCKS]; // deprecated
};

#endif
