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

#ifndef NQPTP_H
#define NQPTP_H

#include <inttypes.h>
#include <pthread.h>

#include "nqptp-shm-structures.h"

#define MAX_CLOCKS 64
#define MAX_CLIENTS 16
#define MAX_OPEN_SOCKETS 16

// When a new timing peer group is created, one of the clocks in the
// group may become the master and its native time becomes the "master time".
// This is what is provided to the client.

// An NQPTP client interface communicates through a shared memory interface named by the
// shm_interface_name It provides the shm_interface_name at the start of every control message it
// sends through port 9000. Following the name, the client can specify the members -- the "PTP
// Instances" -- of a "PTP Network" it wishes to monitor. This is a "timing group" in AirPlay 2
// parlance, it seems.

void send_awakening_announcement_sequence(const uint64_t clock_id, const char *clock_ip,
                                          const int ip_family, const uint8_t priority1,
                                          const uint8_t priority2);

#endif
