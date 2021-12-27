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

#define NQPTP_SHM_STRUCTURES_VERSION 7
#define NQPTP_CONTROL_PORT 9000

// The control port will accept a UDP packet with the first letter being
// "T", followed by the name of the shared memory interface, which should be of
// the form nqptp-<up-to-12-hex-digits>. This can be followed by nothing or by
// a space and then a space-delimited list of ip numbers, either IPv4 or IPv6
// the whole not to exceed 4096 characters in total
// The IPs, if provided, will become the new list of timing peers, clearing or replacing any
// previous list. If the master clock of the new list is the same as that of the old list, it is
// retained without having to resynchronise. This means that non-master devices can be added and
// removed without disturbing the existing-and-continuing master clock.

#include <inttypes.h>
#include <pthread.h>

struct shm_structure {
  pthread_mutex_t shm_mutex;            // for safely accessing the structure
  uint16_t version;                     // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
  uint64_t master_clock_id;             // the current master clock
  char master_clock_ip[64];             // where it's coming from
  uint64_t local_time;                  // the time when the offset was calculated
  uint64_t local_to_master_time_offset; // add this to the local time to get master clock time
  uint64_t master_clock_start_time;     // this is when the master clock became master
};

#endif
