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

#ifndef GENERAL_UTILITIES_H
#define GENERAL_UTILITIES_H

// functions that are pretty generic
// specialised stuff should go in the nqptp-utilities

#include <inttypes.h>
#include <sys/socket.h>
#include <time.h>

// struct sockaddr_in6 is bigger than struct sockaddr. derp
#ifdef AF_INET6
#define SOCKADDR struct sockaddr_storage
#define SAFAMILY ss_family
#else
#define SOCKADDR struct sockaddr
#define SAFAMILY sa_family
#endif

void hcton64(uint64_t num, uint8_t *p);

// these are designed to avoid aliasing check errors
uint64_t nctoh64(const uint8_t *p);
uint32_t nctohl(const uint8_t *p);
uint16_t nctohs(const uint8_t *p);
uint64_t timespec_to_ns(struct timespec *tn);
uint64_t get_time_now();

uint64_t ntoh64(const uint64_t n);

#endif