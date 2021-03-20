/*
 * This file is part of the nqPTP distribution (https://github.com/mikebrady/nqPTP).
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

#define MAX_SHARED_CLOCKS 32
#define NQPTP_SHM_STRUCTURES_VERSION 1

#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>

struct clock_source {
    char ip[64];               // 64 is nicely aligned and bigger than INET6_ADDRSTRLEN (46)
    uint64_t source_time;     // the time at the source at
    uint64_t local_time;       // the local time when the source time is valid
    uint64_t local_to_source_time_offset; // add this to the local time to get source time
    int flags;                 // not used yet
    int valid;                 // this entry is valid
};

struct shm_basic_structure {
};

struct shm_structure {
    pthread_mutex_t shm_mutex; // for safely accessing the structure
    uint16_t size_of_clock_array; // check this is equal to MAX_SHARED_CLOCKS
    uint16_t version; // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
    uint32_t flags;
    struct clock_source clocks[MAX_SHARED_CLOCKS];
};

#endif
