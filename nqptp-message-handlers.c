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
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "general-utilities.h"
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"

void handle_control_port_messages(char *buf, ssize_t recv_len,
                                  clock_source_private_data *clock_private_info) {
  if (recv_len != -1) {
    buf[recv_len - 1] = 0; // make sure there's a null in it!
    debug(1, "New timing peer list: \"%s\".", buf);
    if (buf[0] == 'T') {

      char *ip_list = buf + 1;
      if (*ip_list == ' ')
        ip_list++;

      // turn off all is_timing_peer flags
      int i;
      for (i = 0; i < MAX_CLOCKS; i++) {
        clock_private_info[i].flags &=
            ~(1 << clock_is_a_timing_peer); // turn off peer flag (but not the master flag!)
      }

      while (ip_list != NULL) {
        char *new_ip = strsep(&ip_list, " ");
        // look for the IP in the list of clocks, and create an inert entry if not there
        if ((new_ip != NULL) && (new_ip[0] != 0)) {
          int t = find_clock_source_record(new_ip, clock_private_info);
          if (t == -1)
            t = create_clock_source_record(new_ip, clock_private_info);
          clock_private_info[t].flags |= (1 << clock_is_a_timing_peer);
        }
      }

      // now find and mark the best clock in the timing peer list as the master
      update_master();

      debug(2, "Timing group start");
      for (i = 0; i < MAX_CLOCKS; i++) {
        if ((clock_private_info[i].flags & (1 << clock_is_a_timing_peer)) != 0)
          debug(2, "%s.", &clock_private_info[i].ip);
      }
      debug(2, "Timing group end");

    } else {
      warn("Unrecognised string on the control port.");
    }
  } else {
    warn("Bad packet on the control port.");
  }
}

void handle_announce(char *buf, ssize_t recv_len, clock_source_private_data *clock_private_info,
                     uint64_t reception_time) {
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
        uint64_t grandmaster_clock_id = nctohl(&msg->announce.grandmasterIdentity[0]);
        uint64_t grandmaster_clock_id_low = nctohl(&msg->announce.grandmasterIdentity[4]);
        grandmaster_clock_id = grandmaster_clock_id << 32;
        grandmaster_clock_id = grandmaster_clock_id + grandmaster_clock_id_low;
        uint32_t clockQuality = msg->announce.grandmasterClockQuality;
        uint8_t clockClass = (clockQuality >> 24) & 0xff;
        uint8_t clockAccuracy = (clockQuality >> 16) & 0xff;
        uint16_t offsetScaledLogVariance = clockQuality & 0xffff;
        int best_clock_update_needed = 0;
        if (((clock_private_info->flags & (1 << clock_is_qualified)) == 0) &&
            (msg->announce.stepsRemoved < 255)) {
          // if it's just becoming qualified
          clock_private_info->grandmasterIdentity = grandmaster_clock_id;
          clock_private_info->grandmasterPriority1 = msg->announce.grandmasterPriority1;
          clock_private_info->grandmasterQuality = clockQuality; // class/accuracy/variance
          clock_private_info->grandmasterClass = clockClass;
          clock_private_info->grandmasterAccuracy = clockAccuracy;
          clock_private_info->grandmasterVariance = offsetScaledLogVariance;
          clock_private_info->grandmasterPriority2 = msg->announce.grandmasterPriority2;
          clock_private_info->stepsRemoved = msg->announce.stepsRemoved;
          best_clock_update_needed = 1;
        } else {
          // otherwise, something in it might have changed, I guess, that
          // affects its status as a possible master clock.
          if (clock_private_info->grandmasterIdentity != grandmaster_clock_id) {
            clock_private_info->grandmasterIdentity = grandmaster_clock_id;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterPriority1 != msg->announce.grandmasterPriority1) {
            clock_private_info->grandmasterPriority1 = msg->announce.grandmasterPriority1;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterQuality != clockQuality) {
            clock_private_info->grandmasterQuality = clockQuality;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterClass != clockClass) {
            clock_private_info->grandmasterClass = clockClass;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterAccuracy != clockAccuracy) {
            clock_private_info->grandmasterAccuracy = clockAccuracy;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterVariance != offsetScaledLogVariance) {
            clock_private_info->grandmasterVariance = offsetScaledLogVariance;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->grandmasterPriority2 != msg->announce.grandmasterPriority2) {
            clock_private_info->grandmasterPriority2 = msg->announce.grandmasterPriority2;
            best_clock_update_needed = 1;
          }
          if (clock_private_info->stepsRemoved != msg->announce.stepsRemoved) {
            clock_private_info->stepsRemoved = msg->announce.stepsRemoved;
            best_clock_update_needed = 1;
          }
        }

        if (best_clock_update_needed) {
          debug(2, "best clock update needed");
          debug(2,
                "clock_id %" PRIx64
                " at:    %s, \"Announce\" message is %sQualified -- See 9.3.2.5.",
                clock_private_info->clock_id, clock_private_info->ip,
                clock_private_info->stepsRemoved < 255 ? "" : "not ");
          debug(2, "    grandmasterIdentity:         %" PRIx64 ".", grandmaster_clock_id);
          debug(2, "    grandmasterPriority1:        %u.", msg->announce.grandmasterPriority1);
          debug(2, "    grandmasterClockQuality:     0x%x.", msg->announce.grandmasterClockQuality);
          debug(2, "        clockClass:              %u.", clockClass); // See 7.6.2.4 clockClass
          debug(2, "        clockAccuracy:           0x%x.",
                clockAccuracy); // See 7.6.2.5 clockAccuracy
          debug(2, "        offsetScaledLogVariance: 0x%x.",
                offsetScaledLogVariance); // See 7.6.3 PTP variance
          debug(2, "    grandmasterPriority2:        %u.", msg->announce.grandmasterPriority2);
          debug(2, "    stepsRemoved:                %u.", msg->announce.stepsRemoved);

          // now go and re-mark the best clock in the timing peer list
          if (clock_private_info->stepsRemoved >= 255) // 9.3.2.5 (d)
            clock_private_info->flags &= ~(1 << clock_is_qualified);
          else
            clock_private_info->flags |= (1 << clock_is_qualified);
          update_master();
        }
      } else {
        if ((clock_private_info->flags & (1 << clock_is_qualified)) !=
            0) // if it was qualified, but now isn't
          debug(2,
                "clock_id %" PRIx64
                " on ip: %s \"Announce\" message is not Qualified -- See 9.3.2.5.",
                clock_private_info->clock_id, clock_private_info->ip);
        clock_private_info->flags &= ~(1 << clock_is_qualified);
      }
    }
  }
}

void handle_follow_up(char *buf, __attribute__((unused)) ssize_t recv_len,
                      clock_source_private_data *clock_private_info, uint64_t reception_time) {
  if ((clock_private_info->flags & (1 << clock_is_master)) != 0) {
	  debug(2, "FOLLOWUP from %" PRIx64 ", %s.", clock_private_info->clock_id, &clock_private_info->ip);
    struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;

    uint64_t packet_clock_id = nctohl(&msg->header.clockIdentity[0]);
    uint64_t packet_clock_id_low = nctohl(&msg->header.clockIdentity[4]);
    packet_clock_id = packet_clock_id << 32;
    packet_clock_id = packet_clock_id + packet_clock_id_low;

    uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
    uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
    uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
    uint64_t preciseOriginTimestamp = seconds_hi;
    preciseOriginTimestamp = preciseOriginTimestamp << 32;
    preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
    preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
    preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;

    // preciseOriginTimestamp is called "t1" in the IEEE spec.
    // we are using the reception time here as t2, which is a hack

    // check to see the difference between the previous preciseOriginTimestamp

    // update the shared clock information
    uint64_t offset = preciseOriginTimestamp - reception_time;

    int64_t jitter = 0;
    // if there has never been a previous follow_up or if it was long ago (more than 15 seconds),
    // don't use it
    if (clock_private_info->previous_offset_time != 0) {
      int64_t time_since_last_sync = reception_time - clock_private_info->last_sync_time;
      int64_t sync_timeout = 60000000000; // nanoseconds
      debug(2, "Sync interval: %f seconds.", 0.000000001 * time_since_last_sync);
      if (time_since_last_sync < sync_timeout) {
        // do acceptance checking
        // if the new offset is greater, by any amount, than the old offset
        // accept it
        // if it is less than the new offset by up to what a reasonable drift divergence would allow
        // accept it
        // otherwise, reject it
        // drift divergence of 1000 ppm (which is huge) would give 125 us per 125 ms.

        jitter = offset - clock_private_info->previous_offset;

        uint64_t jitter_timing_interval = reception_time - clock_private_info->previous_offset_time;
        long double jitterppm = 0.0;
        if (jitter_timing_interval != 0) {
          jitterppm = (0.001 * (jitter * 1000000000)) / jitter_timing_interval;
          debug(2, "jitter: %" PRId64 " in: %" PRId64 " ns, %+f ppm ", jitter,
                jitter_timing_interval, jitterppm);
        }
        if (jitterppm >= -1000) {
          // we take a positive or small negative jitter as a sync event
          // as we have a new figure for the difference between the local clock and the
          // remote clock which is almost the same or greater than our previous estimate
          clock_private_info->last_sync_time = reception_time;
        } else {
          // let our previous estimate drop by some parts-per-million
          // jitter = (-100 * jitter_timing_interval) / 1000000;
          jitter = -10 * 1000; // this is nanoseconds in, supposedly, 125 milliseconds. 12.5 us /
                               // 125 ms is 100 ppm.
          offset = clock_private_info->previous_offset + jitter;
        }
      } else {
        warn("Lost sync with clock %" PRIx64 " at %s. Resynchronising.",
             clock_private_info->clock_id, clock_private_info->ip);
        // leave the offset as it was coming in and take it as a sync time
        clock_private_info->last_sync_time = reception_time;
      }
    } else {
      clock_private_info->last_sync_time = reception_time;
    }

    // uint64_t estimated_offset = offset;

    uint32_t old_flags = clock_private_info->flags;

    if ((clock_private_info->flags & (1 << clock_is_valid)) == 0) {
      debug(1, "clock %" PRIx64 " is now valid at: %s", packet_clock_id, clock_private_info->ip);
    }
    clock_private_info->clock_id = packet_clock_id;
    clock_private_info->flags |= (1 << clock_is_valid);
    clock_private_info->local_time = reception_time;
    clock_private_info->origin_time = preciseOriginTimestamp;
    clock_private_info->local_to_source_time_offset = offset;

    if (old_flags != clock_private_info->flags) {
      update_master();
    } else if ((clock_private_info->flags & (1 << clock_is_master)) != 0) {
      update_master_clock_info(clock_private_info->clock_id, (const char *)&clock_private_info->ip,
                               reception_time, offset);
      debug(1, "clock: %" PRIx64 ", time: %" PRIu64 ", offset: %" PRId64 ", jitter: %+f ms.", clock_private_info->clock_id, reception_time, offset,
            0.000001 * jitter);
    }

    clock_private_info->previous_offset = offset;
    clock_private_info->previous_offset_time = reception_time;
  }
}
