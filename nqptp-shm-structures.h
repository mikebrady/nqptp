/*
 * This file is part of the nqptp distribution (https://github.com/mikebrady/nqptp).
 * Copyright (c) 2021--2022 Mike Brady.
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

#define NQPTP_INTERFACE_NAME "/nqptp"

#define NQPTP_SHM_STRUCTURES_VERSION 8
#define NQPTP_CONTROL_PORT 9000

// The control port expects a UDP packet with the first space-delimited string
// being the name of the shared memory interface (SMI) to be used.
// This allows client applications to have a dedicated named SMI interface with
// a timing peer list independent of other clients.
// The name given must be a valid SMI name and must contain no spaces.
// If the named SMI interface doesn't exist it will be created by NQPTP.
// The SMI name should be delimited by a space and followed by a command letter.
// At present, the only command is "T", which must followed by nothing or by
// a space and a space-delimited list of IPv4 or IPv6 numbers,
// the whole not to exceed 4096 characters in total.
// The IPs, if provided, will become the new list of timing peers, replacing any
// previous list. If the master clock of the new list is the same as that of the old list,
// the master clock is retained without resynchronisation; this means that non-master
// devices can be added and removed without disturbing the SMI's existing master clock.
// If no timing list is provided, the existing timing list is deleted.
// (In future version of NQPTP the SMI interface may also be deleted at this point.)
// SMI interfaces are not currently deleted or garbage collected.

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
