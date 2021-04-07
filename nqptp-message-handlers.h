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

#ifndef NQPTP_MESSAGE_HANDLERS_H
#define NQPTP_MESSAGE_HANDLERS_H

#include "nqptp-clock-sources.h"
#include "nqptp-shm-structures.h"

void handle_announce(char *buf, ssize_t recv_len, clock_source *clock_info,
                     clock_source_private_data *clock_private_info, uint64_t reception_time);

void handle_follow_up(char *buf, ssize_t recv_len, clock_source *clock_info,
                     clock_source_private_data *clock_private_info, uint64_t reception_time, pthread_mutex_t *shm_mutex);

void handle_control_port_messages(char *buf, ssize_t recv_len, clock_source *clock_info,
                                  clock_source_private_data *clock_private_info);

#endif