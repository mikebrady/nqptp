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

#ifndef NQPTP_UTILITIES_H
#define NQPTP_UTILITIES_H

#include "nqptp.h"
#include <inttypes.h>
#include <pthread.h>

// functions that are specific to NQPTP
// general stuff should go in the general-utilities

typedef struct {
  int number;
  uint16_t port;
  int family; // AF_INET or AF_INET6
} socket_info;

typedef struct {
  unsigned int sockets_open; // also doubles as where to put next one, as sockets are never closed.
  socket_info sockets[MAX_OPEN_SOCKETS];
} sockets_open_bundle;

void open_sockets_at_port(const char *node, uint16_t port, sockets_open_bundle *sockets_open_stuff);
void debug_print_buffer(int level, char *buf, size_t buf_len);
uint64_t get_self_clock_id(); // a clock ID based on a MAC address
#endif