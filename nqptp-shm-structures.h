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
#define NQPTP_SHM_STRUCTURES_VERSION 6
#define NQPTP_CONTROL_PORT 9000

// the control port will accept a UDP packet with the first letter being:
// "T", followed by a space and then a space-delimited
// list of ip numbers, either IPv4 or IPv6
// the whole not to exceed 4096 characters in total
// The IPs will become the new list of timing peers, replacing any previous

#include <inttypes.h>
#include <pthread.h>

struct shm_structure {
  pthread_mutex_t shm_mutex;            // for safely accessing the structure
  uint16_t version;                     // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint32_t flags;                       // unused
  uint64_t master_clock_id;             // the current master clock
  char master_clock_ip[64];             // where it's coming from
  uint64_t local_time;                  // the time when the offset was calculated
  uint64_t local_to_master_time_offset; // add this to the local time to get master clock time
  uint64_t master_clock_start_time;     // this is when the master clock became master
};

#endif
