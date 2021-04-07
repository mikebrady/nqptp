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
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"
#include <string.h>

#include "debug.h"
#include "general-utilities.h"

void handle_control_port_messages(char *buf, ssize_t recv_len, clock_source *clock_info,
                                  clock_source_private_data *clock_private_info) {
  if (recv_len != -1) {
    buf[recv_len - 1] = 0; // make sure there's a null in it!
    if (strstr(buf, "set_timing_peers ") == buf) {
      char *ip_list = buf + strlen("set_timing_peers ");

      int rc = pthread_mutex_lock(&shared_memory->shm_mutex);
      if (rc != 0)
        warn("Can't acquire mutex to set_timing_peers!");
      // turn off all is_timing_peers
      int i;
      for (i = 0; i < MAX_CLOCKS; i++)
        clock_info[i].timing_peer = 0;

      while (ip_list != NULL) {
        char *new_ip = strsep(&ip_list, " ");
        // look for the IP in the list of clocks, and create an inert entry if not there
        int t = find_clock_source_record(new_ip, clock_info, clock_private_info);
        if (t == -1)
          t = create_clock_source_record(new_ip, clock_info, clock_private_info,
                                         0); // don't use the mutex

        clock_info[t].timing_peer = 1;
      }

      rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
      if (rc != 0)
        warn("Can't release mutex after set_timing_peers!");

      for (i = 0; i < MAX_CLOCKS; i++) {
        if (clock_info[i].timing_peer != 0)
          debug(3, "%s is in the timing peer group.", &clock_info[i].ip);
      }
    } else {
      warn("Unrecognised string on the control port.");
    }
  } else {
    warn("Bad packet on the control port.");
  }
}

void handle_announce(char *buf, ssize_t recv_len, clock_source *clock_info,
                     clock_source_private_data *clock_private_info, uint64_t reception_time) {
  // reject Announce messages from self
  if (clock_private_info->is_one_of_ours == 0) {
    // debug_print_buffer(1, buf, (size_t) recv_len);
    // make way for the new time
    if ((size_t)recv_len >= sizeof(struct ptp_announce_message)) {
      struct ptp_announce_message *msg = (struct ptp_announce_message *)buf;

      int i;
      // number of elements in the array is 4, hence the 4-1 stuff
      for (i = 4 - 1; i > 1 - 1; i--) {
        clock_private_info->announce_times[i] = clock_private_info->announce_times[i - 1];
      };
      clock_private_info->announce_times[0] = reception_time;

      // so, we have added a new element and assumed that
      // now we need to walk down the array checking that non of the elements are too old
      i = 0;
      int valid_count = 0;
      int finished = 0;

      // see 9.3.2.4.4 and 9.3.2.5
      uint64_t foreign_master_time_window = 1;
      foreign_master_time_window = foreign_master_time_window
                                   << (32 + aPTPinitialLogAnnounceInterval);
      foreign_master_time_window = foreign_master_time_window * 4;
      foreign_master_time_window = foreign_master_time_window >> 32; // should be 4 seconds

      uint64_t cutoff_time = reception_time + foreign_master_time_window;
      int foreign_master_threshold = 2;
      while ((i < 4) && (finished == 0)) {
        int64_t delta = cutoff_time - clock_private_info->announce_times[i];
        if (delta > 0)
          valid_count++;
        else
          finished = 1;
        i++;
      }
      if (valid_count >= foreign_master_threshold) {
        if (clock_info->qualified == 0) {
          uint64_t grandmaster_clock_id = nctohl(&msg->announce.grandmasterIdentity[0]);
          uint64_t grandmaster_clock_id_low = nctohl(&msg->announce.grandmasterIdentity[4]);
          grandmaster_clock_id = grandmaster_clock_id << 32;
          grandmaster_clock_id = grandmaster_clock_id + grandmaster_clock_id_low;

          debug(2,
                "clock_id %" PRIx64 " at:    %s, \"Announce\" message is Qualified -- See 9.3.2.5.",
                clock_info->clock_id, clock_info->ip);
          uint32_t clockQuality = msg->announce.grandmasterClockQuality;
          uint8_t clockClass = (clockQuality >> 24) & 0xff;
          uint8_t clockAccuracy = (clockQuality >> 16) & 0xff;
          uint16_t offsetScaledLogVariance = clockQuality & 0xffff;
          debug(2, "    grandmasterIdentity:         %" PRIx64 ".", grandmaster_clock_id);
          debug(2, "    grandmasterPriority1:        %u.", msg->announce.grandmasterPriority1);
          debug(2, "    grandmasterClockQuality:     0x%x.", msg->announce.grandmasterClockQuality);
          debug(2, "        clockClass:              %u.", clockClass); // See 7.6.2.4 clockClass
          debug(2, "        clockAccuracy:           0x%x.",
                clockAccuracy); // See 7.6.2.5 clockAccuracy
          debug(2, "        offsetScaledLogVariance: 0x%x.",
                offsetScaledLogVariance); // See 7.6.3 PTP variance
          debug(2, "    grandmasterPriority2:        %u.", msg->announce.grandmasterPriority2);
        }
        if (pthread_mutex_lock(&shared_memory->shm_mutex) != 0)
          warn("Can't acquire mutex to set_timing_peers!");
        clock_info->qualified = 1;
        if (pthread_mutex_unlock(&shared_memory->shm_mutex) != 0)
          warn("Can't release mutex after set_timing_peers!");
      } else {
        if (clock_info->qualified != 0)
          debug(1,
                "clock_id %" PRIx64
                " on ip: %s \"Announce\" message is not Qualified -- See 9.3.2.5.",
                clock_info->clock_id, clock_info->ip);
        if (pthread_mutex_lock(&shared_memory->shm_mutex) != 0)
          warn("Can't acquire mutex to set_timing_peers!");
        clock_info->qualified = 0;
        if (pthread_mutex_unlock(&shared_memory->shm_mutex) != 0)
          warn("Can't release mutex after set_timing_peers!");
      }
    }
  }
}
