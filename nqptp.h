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
// group becomes the master and its native time becomes the "master time".
// This is what is provided to the client.

extern int master_clock_index;
extern struct shm_structure *shared_memory;

void update_master_clock_info(uint64_t master_clock_id, uint64_t local_time,
                              uint64_t local_to_master_offset);

#endif