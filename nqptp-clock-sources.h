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

#ifndef NQPTP_CLOCK_SOURCES_H
#define NQPTP_CLOCK_SOURCES_H

#include "nqptp-shm-structures.h"
#include "nqptp.h"

typedef enum { clock_is_in_use, clock_is_master } clock_flags;

// information about each clock source
typedef struct {
  char ip[64]; // 64 is nicely aligned and bigger than INET6_ADDRSTRLEN (46)
  int family;  // AF_INET or AF_INET6
  int follow_up_number;
  int announcements_without_followups; // add 1 for every announce, reset with a followup
  uint64_t clock_id;
  uint64_t previous_offset, previous_offset_time, previous_offset_grandmaster,
      previous_preciseOriginTimestamp;
  uint64_t mastership_start_time; // set to the time of the first sample used as master

  // for garbage collection
  uint64_t time_of_last_use; // will be taken out of use if not used for a while and not in the
                             // timing peer group
  uint8_t flags;             // stuff related specifically to the clock itself

  // these are for finding the best clock to use
  // See Figure 27 and 27 pp 89 -- 90 for the Data set comparison algorithm
  uint16_t clock_port_number; // used along with the clock_id as the portIdentity
  uint8_t grandmasterPriority1;
  uint32_t grandmasterQuality; // class/accuracy/variance -- lower is better
  uint8_t grandmasterClass;
  uint8_t grandmasterAccuracy;
  uint16_t grandmasterVariance;
  uint8_t grandmasterPriority2;
  uint64_t grandmasterIdentity;
  uint16_t stepsRemoved;
  int identical_previous_preciseOriginTimestamp_count;
  int wakeup_sent;

} clock_source_private_data;

// information on each client
typedef struct {
  int shm_fd;
  struct shm_structure *shared_memory; // the client's individual smi interface
  char shm_interface_name[64];         // it's name
  int client_id; // the 1-based index number of clocks' client_flags field associated with this
                 // interface
} client_record;

extern int shm_fd;
extern struct shm_structure *shared_memory;

int find_clock_source_record(char *sender_string, clock_source_private_data *clocks_private_info);

int create_clock_source_record(char *sender_string, clock_source_private_data *clocks_private_info);

void update_clock_self_identifications(clock_source_private_data *clocks_private_info);

void manage_clock_sources(uint64_t reception_time, clock_source_private_data *clocks_private_info);

int get_client_id(char *client_shared_memory_interface_name);
const char *get_client_name(int client_id);
int delete_client(int client_id);
int delete_clients();

extern clock_source_private_data clocks_private[MAX_CLOCKS];

void update_master_clock_info(uint64_t master_clock_id, const char *ip, uint64_t local_time,
                              uint64_t local_to_master_offset, uint64_t mastership_start_time);

#endif
