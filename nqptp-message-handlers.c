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
#include <arpa/inet.h> // ntohl and ntohs
#include <string.h>    //strsep

#include "debug.h"
#include "general-utilities.h"
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"

void handle_control_port_messages(char *buf, ssize_t recv_len,
                                  clock_source_private_data *clock_private_info) {
  if (recv_len != -1) {
    buf[recv_len - 1] = 0; // make sure there's a null in it!
    debug(2, "New timing peer list: \"%s\".", buf);
    if (buf[0] == 'T') {

      char *ip_list = buf + 1;
      if (*ip_list == ' ')
        ip_list++;

      // turn off all is_timing_peer flags
      int i;
      for (i = 0; i < MAX_CLOCKS; i++) {
        clock_private_info[i].flags &=
            ~(1 << clock_is_a_timing_peer); // turn off peer flag (but not the master flag!)
        clock_private_info[i].announcements_without_followups = 0; // to allow a possibly silent clocks to be revisited when added to a timing peer list
      }

      while (ip_list != NULL) {
        char *new_ip = strsep(&ip_list, " ");
        // look for the IP in the list of clocks, and create an inert entry if not there
        if ((new_ip != NULL) && (new_ip[0] != 0)) {
          int t = find_clock_source_record(new_ip, clock_private_info);
          if (t == -1)
            t = create_clock_source_record(new_ip, clock_private_info);
          if (t != -1) // if the clock table is not full, show it's a timing peer
            clock_private_info[t].flags |= (1 << clock_is_a_timing_peer);
          // otherwise, drop it
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

      uint64_t packet_clock_id = nctohl(&msg->header.clockIdentity[0]);
      uint64_t packet_clock_id_low = nctohl(&msg->header.clockIdentity[4]);
      packet_clock_id = packet_clock_id << 32;
      packet_clock_id = packet_clock_id + packet_clock_id_low;
      clock_private_info->clock_id = packet_clock_id;
      clock_private_info->grandmasterPriority1 =
          msg->announce.grandmasterPriority1; // need this for possibly pinging it later...
      clock_private_info->grandmasterPriority2 =
          msg->announce.grandmasterPriority2; // need this for possibly pinging it later...

      debug(2, "announcement seen from %" PRIx64 " at %s.", clock_private_info->clock_id,
            clock_private_info->ip);

      if (clock_private_info->announcements_without_followups < 5)
        clock_private_info->announcements_without_followups++;

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
        uint32_t clockQuality = ntohl(msg->announce.grandmasterClockQuality);
        uint8_t clockClass = (clockQuality >> 24) & 0xff;
        uint8_t clockAccuracy = (clockQuality >> 16) & 0xff;
        uint16_t offsetScaledLogVariance = clockQuality & 0xffff;
        uint16_t stepsRemoved = ntohs(msg->announce.stepsRemoved);
        uint16_t sourcePortID = ntohs(msg->header.sourcePortID);
        int best_clock_update_needed = 0;
        if (((clock_private_info->flags & (1 << clock_is_qualified)) == 0) &&
            (stepsRemoved < 255)) {
          // if it's just becoming qualified
          clock_private_info->grandmasterIdentity = grandmaster_clock_id;
          clock_private_info->grandmasterPriority1 = msg->announce.grandmasterPriority1;
          clock_private_info->grandmasterQuality = clockQuality; // class/accuracy/variance
          clock_private_info->grandmasterClass = clockClass;
          clock_private_info->grandmasterAccuracy = clockAccuracy;
          clock_private_info->grandmasterVariance = offsetScaledLogVariance;
          clock_private_info->grandmasterPriority2 = msg->announce.grandmasterPriority2;
          clock_private_info->stepsRemoved = stepsRemoved;
          clock_private_info->clock_port_number = sourcePortID;
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
          if (clock_private_info->stepsRemoved != stepsRemoved) {
            clock_private_info->stepsRemoved = stepsRemoved;
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
          debug(2, "    grandmasterClockQuality:     0x%x.", clockQuality);
          debug(2, "        clockClass:              %u.", clockClass); // See 7.6.2.4 clockClass
          debug(2, "        clockAccuracy:           0x%x.",
                clockAccuracy); // See 7.6.2.5 clockAccuracy
          debug(2, "        offsetScaledLogVariance: 0x%x.",
                offsetScaledLogVariance); // See 7.6.3 PTP variance
          debug(2, "    grandmasterPriority2:        %u.", msg->announce.grandmasterPriority2);
          debug(2, "    stepsRemoved:                %u.", stepsRemoved);
          debug(2, "    portNumber:                  %u.", sourcePortID);

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

  struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;

  uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
  uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
  uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
  uint64_t preciseOriginTimestamp = seconds_hi;
  preciseOriginTimestamp = preciseOriginTimestamp << 32;
  preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
  preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
  preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;

  // update our sample information
  if (clock_private_info->follow_up_number < 100)
    clock_private_info->follow_up_number++;

  clock_private_info->announcements_without_followups = 0; // we've seen a followup

  clock_private_info->samples[clock_private_info->next_sample_goes_here].local_time =
      reception_time;
  clock_private_info->samples[clock_private_info->next_sample_goes_here].clock_time =
      preciseOriginTimestamp;

  if (clock_private_info->vacant_samples > 0)
    clock_private_info->vacant_samples--;

  clock_private_info->next_sample_goes_here++;
  // if we have need to wrap.
  if (clock_private_info->next_sample_goes_here == MAX_TIMING_SAMPLES)
    clock_private_info->next_sample_goes_here = 0;

  debug(2, "FOLLOWUP from %" PRIx64 ", %s.", clock_private_info->clock_id, &clock_private_info->ip);
  uint64_t offset = preciseOriginTimestamp - reception_time;

  clock_private_info->local_time = reception_time;
  clock_private_info->source_time = preciseOriginTimestamp;
  clock_private_info->local_to_source_time_offset = offset;

  int64_t jitter = 0;

  int64_t time_since_previous_offset = 0;

  if (clock_private_info->previous_offset_time != 0) {
    time_since_previous_offset = reception_time - clock_private_info->previous_offset_time;
  }


  if ((clock_private_info->flags & (1 << clock_is_becoming_master)) != 0) {
    // we definitely have at least one sample since the request was made to
    // designate it a master, so we assume it is legitimate. That is, we assume
    // that the clock originator knows that it a clock master by now.
    uint64_t oldest_acceptable_master_clock_time =
        clock_private_info->source_time + 1150000000; // ns.

    // we will try to improve on this present, definitive, local_to_source_time_offset we have
    int changes_made = 0;

    uint64_t best_offset_so_far = clock_private_info->local_to_source_time_offset;
    uint64_t age_of_oldest_legitimate_sample = clock_private_info->local_time;

    int number_of_samples = MAX_TIMING_SAMPLES - clock_private_info->vacant_samples;
    int samples_checked = 0;
    if (number_of_samples > 0) {
      debug(3, "Number of samples: %d.", number_of_samples);

      // Now we use the last few samples to calculate the best offset for the
      // new master clock.

      // The time of the oldest sample we use will become the time of the start of the
      // mastership.

      // We will accept samples that would make the local-to-clock offset greatest,
      // provided they are not too old and that they don't push the current clock time
      // more than, say, 1000 ms plus one sample interval (i.e about 1.125 seconds) in the future.

      // This present sample is the only time estimate we have when the clock is definitely a
      // master, so we use it to eliminate any previous time estimates, made when the clock wasn't
      // designated a master, that would put it more than, say, a 1.15 seconds further into the
      // future.

      // Allow the samples to give a valid master clock time up to this much later than the
      // present, definitive, sample:

      uint64_t oldest_acceptable_time = reception_time - 10000000000; // only go back this far (ns)

      int64_t cko = age_of_oldest_legitimate_sample - oldest_acceptable_time;
      if (cko < 0)
        debug(1, "starting sample is too old: %" PRId64 " ns.", cko);

      int i;
      for (i = 0; i < number_of_samples; i++) {
        int64_t age = reception_time - clock_private_info->samples[i].local_time;
        int64_t age_relative_to_oldest_acceptable_time =
            clock_private_info->samples[i].local_time - oldest_acceptable_time;
        if (age_relative_to_oldest_acceptable_time > 0) {
          debug(3, "sample accepted at %f seconds old.", 0.000000001 * age);
          if (clock_private_info->samples[i].local_time < age_of_oldest_legitimate_sample) {
            age_of_oldest_legitimate_sample = clock_private_info->samples[i].local_time;
          }
          uint64_t possible_offset =
              clock_private_info->samples[i].clock_time - clock_private_info->samples[i].local_time;
          uint64_t possible_master_clock_time = clock_private_info->local_time + possible_offset;
          int64_t age_relative_to_oldest_acceptable_master_clock_time =
              possible_master_clock_time - oldest_acceptable_master_clock_time;
          if (age_relative_to_oldest_acceptable_master_clock_time <= 0) {
            samples_checked++;
            // so, the sample was not obtained too far in the past
            // and it would not push the estimated master clock_time too far into the future
            // so, if it is greater than the best_offset_so_far, then make it the new one
            if (possible_offset > best_offset_so_far) {
              debug(3, "new best offset");
              best_offset_so_far = possible_offset;
              changes_made++;
            }
          } else {
            debug(3, "sample too far into the future");
          }
        } else {
          debug(3, "sample too old at %f seconds old.", 0.000000001 * age);
        }
      }
    }
    clock_private_info->mastership_start_time = age_of_oldest_legitimate_sample;
    int64_t offset_difference =
        best_offset_so_far - clock_private_info->local_to_source_time_offset;

    debug(2, "Lookback difference: %f ms with %d samples checked of %d samples total.",
          0.000001 * offset_difference, samples_checked, number_of_samples);
    clock_private_info->local_to_source_time_offset = best_offset_so_far;

    debug(2, "Master sampling started %f ms before becoming master.",
          0.000001 * (reception_time - age_of_oldest_legitimate_sample));
    clock_private_info->flags &= ~(1 << clock_is_becoming_master);
    clock_private_info->flags |= 1 << clock_is_master;
    clock_private_info->previous_offset_time = 0;
    debug_log_nqptp_status(2);
  } else if ((clock_private_info->previous_offset_time != 0) && (time_since_previous_offset < 300000000000)) {
    // i.e. if it's not becoming a master and there has been a previous follow_up
    int64_t time_since_last_sync = reception_time - clock_private_info->last_sync_time;
    int64_t sync_timeout = 300000000000; // nanoseconds
    debug(2, "Sync interval: %f seconds.", 0.000000001 * time_since_last_sync);
    if (time_since_last_sync < sync_timeout) {

      // Do acceptance checking.

      // Positive changes in the offset are much more likely to be
      // legitimate, since they could only occur due to a shorter
      // propagation time. (Actually, this is not quite true --
      // it is possible that the remote clock could be adjusted forward
      // and this would increase the offset too.)
      // Anyway, when the clock is new, we give preferential weighting to
      // positive changes in the offset.

      // If the new offset is greater, by any amount, than the old offset,
      // or if it is less by up to 10 mS,
      // accept it.
      // Otherwise, drop it

      // This seems to be quite stable

      jitter = offset - clock_private_info->previous_offset;

      if (jitter > -10000000) {
        // we take any positive or a limited negative jitter as a sync event
        if (jitter < 0) {
          if (clock_private_info->follow_up_number <
                 (5 * 8)) // at the beginning (8 samples per second)
            offset = clock_private_info->previous_offset + jitter / 16;
          else
            offset = clock_private_info->previous_offset + jitter / 64;
        } else if (clock_private_info->follow_up_number <
                 (5 * 8)) // at the beginning (8 samples per second)
          offset =
              clock_private_info->previous_offset + jitter / 1; // accept positive changes quickly
        else
          offset = clock_private_info->previous_offset + jitter / 64;
        clock_private_info->last_sync_time = reception_time;
      } else {
        offset = clock_private_info->previous_offset; // forget the present sample...
      }
    } else {
      if ((clock_private_info->flags & (1 << clock_is_master)) != 0)
        debug(1, "Resynchronising master clock %" PRIx64 " at %s.", clock_private_info->clock_id,
              clock_private_info->ip);
      // leave the offset as it was coming in and take it as a sync time
      clock_private_info->last_sync_time = reception_time;
    }
  } else {
    clock_private_info->last_sync_time = reception_time;
    if (time_since_previous_offset >= 300000000000) {
      debug(1,"Long interval: %f seconds since previous follow_up", time_since_previous_offset * 1E-9);
      clock_private_info->mastership_start_time = reception_time; // mastership is reset to this time...
      clock_private_info->previous_offset_time = 0;
    }
  }

  clock_private_info->previous_offset = offset;
  clock_private_info->previous_offset_time = reception_time;

  if ((clock_private_info->flags & (1 << clock_is_master)) != 0) {
    update_master_clock_info(clock_private_info->clock_id, (const char *)&clock_private_info->ip,
                             reception_time, offset, clock_private_info->mastership_start_time);
    debug(3, "clock: %" PRIx64 ", time: %" PRIu64 ", offset: %" PRId64 ", jitter: %+f ms.",
          clock_private_info->clock_id, reception_time, offset, 0.000001 * jitter);
  }

  if ((clock_private_info->flags & (1 << clock_is_valid)) == 0) {
    debug(2, "follow_up seen from %" PRIx64 " at %s.", clock_private_info->clock_id,
          clock_private_info->ip);
    clock_private_info->flags |=
        (1 << clock_is_valid); // valid because it has at least one follow_up
    update_master();
  }
}
