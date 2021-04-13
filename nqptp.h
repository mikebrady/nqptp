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

#ifndef NQPTP_H
#define NQPTP_H

#include "nqptp-shm-structures.h"

#define MAX_OPEN_SOCKETS 16


// When a new timing peer group is created, one of the clocks in the
// group becomes the master and its "native" time becomes the clock's "PTP time".
// This is what is provided to the client.

// If another clock becomes the new master, then its "native" time will
// generally be different from PTP time.
// The offset from the new master's time to PTP time
// will be added to the master's time to translate it to PTP time.

// You can create a _new_ timing peer group, which starts with a zero
// master_clock_to_ptp_offset and thus sets the PTP time to the native time
// of the first clock master of the group, as nature intended.

// Alternatively, you can _update_ an existing timing peer group, which calculates an
// appropriate master_clock_to_ptp_offset to preserve timing relative to
// the existing PTP time, ensuring that PTP time remain consistent even
// when the clock master changes.

extern int master_clock_index;
extern uint64_t master_clock_to_ptp_offset;
extern struct shm_structure *shared_memory;

#endif