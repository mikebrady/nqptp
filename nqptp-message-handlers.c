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
        clock_info[i].flags &= ~(1 << clock_is_a_timing_peer); // turn off peer flags

      while (ip_list != NULL) {
        char *new_ip = strsep(&ip_list, " ");
        // look for the IP in the list of clocks, and create an inert entry if not there
        if ((new_ip != NULL) && (new_ip[0] != 0)) {
          int t = find_clock_source_record(new_ip, clock_info, clock_private_info);
          if (t == -1)
            t = create_clock_source_record(new_ip, clock_info, clock_private_info,
                                           0); // don't use the mutex

          // if it is just about to become a timing peer, reset its sample count
          clock_private_info[t].vacant_samples = MAX_TIMING_SAMPLES;
          clock_private_info[t].next_sample_goes_here = 0;

          clock_info[t].flags |= (1 << clock_is_a_timing_peer);
        }
      }

      rc = pthread_mutex_unlock(&shared_memory->shm_mutex);
      if (rc != 0)
        warn("Can't release mutex after set_timing_peers!");
      debug(1, "Timing group start");
      for (i = 0; i < MAX_CLOCKS; i++) {
        if ((clock_info[i].flags & (1 << clock_is_a_timing_peer)) != 0)
          debug(1, "%s.", &clock_info[i].ip);
      }
      debug(1, "Timing group end");

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
        if ((clock_info->flags & (1 << clock_is_qualified)) == 0) {
          uint64_t grandmaster_clock_id = nctohl(&msg->announce.grandmasterIdentity[0]);
          uint64_t grandmaster_clock_id_low = nctohl(&msg->announce.grandmasterIdentity[4]);
          grandmaster_clock_id = grandmaster_clock_id << 32;
          grandmaster_clock_id = grandmaster_clock_id + grandmaster_clock_id_low;

          debug(1,
                "clock_id %" PRIx64 " at:    %s, \"Announce\" message is Qualified -- See 9.3.2.5.",
                clock_info->clock_id, clock_info->ip);
          uint32_t clockQuality = msg->announce.grandmasterClockQuality;
          uint8_t clockClass = (clockQuality >> 24) & 0xff;
          uint8_t clockAccuracy = (clockQuality >> 16) & 0xff;
          uint16_t offsetScaledLogVariance = clockQuality & 0xffff;
          debug(1, "    grandmasterIdentity:         %" PRIx64 ".", grandmaster_clock_id);
          debug(1, "    grandmasterPriority1:        %u.", msg->announce.grandmasterPriority1);
          debug(1, "    grandmasterClockQuality:     0x%x.", msg->announce.grandmasterClockQuality);
          debug(1, "        clockClass:              %u.", clockClass); // See 7.6.2.4 clockClass
          debug(1, "        clockAccuracy:           0x%x.",
                clockAccuracy); // See 7.6.2.5 clockAccuracy
          debug(1, "        offsetScaledLogVariance: 0x%x.",
                offsetScaledLogVariance); // See 7.6.3 PTP variance
          debug(1, "    grandmasterPriority2:        %u.", msg->announce.grandmasterPriority2);
        }
        if (pthread_mutex_lock(&shared_memory->shm_mutex) != 0)
          warn("Can't acquire mutex to set_timing_peers!");
        clock_info->flags |= (1 << clock_is_qualified);
        if (pthread_mutex_unlock(&shared_memory->shm_mutex) != 0)
          warn("Can't release mutex after set_timing_peers!");
      } else {
        if ((clock_info->flags & (1 << clock_is_qualified)) !=
            0) // if it was qualified, but now isn't
          debug(1,
                "clock_id %" PRIx64
                " on ip: %s \"Announce\" message is not Qualified -- See 9.3.2.5.",
                clock_info->clock_id, clock_info->ip);
        if (pthread_mutex_lock(&shared_memory->shm_mutex) != 0)
          warn("Can't acquire mutex to set_timing_peers!");
        clock_info->flags &= ~(1 << clock_is_qualified);
        if (pthread_mutex_unlock(&shared_memory->shm_mutex) != 0)
          warn("Can't release mutex after set_timing_peers!");
      }
    }
  }
}

void handle_sync(char *buf, ssize_t recv_len, clock_source *clock_info,
                 clock_source_private_data *clock_private_info, uint64_t reception_time) {

  struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
  // this is just to see if anything interesting comes in the SYNC package
  // a non-zero origin timestamp
  // or correction field would be interesting....
  int ck;
  int non_empty_origin_timestamp = 0;
  for (ck = 0; ck < 10; ck++) {
    if (msg->sync.originTimestamp[ck] != 0) {
      non_empty_origin_timestamp = (non_empty_origin_timestamp | 1);
    }
  }
  if (non_empty_origin_timestamp != 0)
    debug(2, "Sync Origin Timestamp!");
  if (msg->header.correctionField != 0)
    debug(3, "correctionField: %" PRIx64 ".", msg->header.correctionField);

  int discard_sync = 0;

  // check if we should discard this SYNC
  if (clock_private_info->current_stage != waiting_for_sync) {

    // here, we have an unexpected SYNC. It could be because the
    // previous transaction sequence failed for some reason
    // But, if that is so, the SYNC will have a newer sequence number
    // so, ignore it if it's a little older.

    // If it seems a lot older in sequence number terms, then it might
    // be the start of a completely new sequence, so if the
    // difference is more than 40 (WAG), accept it

    uint16_t new_sync_sequence_number = ntohs(msg->header.sequenceId);
    int16_t sequence_number_difference =
        (clock_private_info->sequence_number - new_sync_sequence_number);

    if ((sequence_number_difference > 0) && (sequence_number_difference < 40))
      discard_sync = 1;
  }

  if (discard_sync == 0) {
    /*
        // just check how long since the last sync, if there was one
        clock_private_info->reception_interval = 0;
        if (clock_private_info->t2 != 0) {
          int16_t seq_diff = ntohs(msg->header.sequenceId) - clock_private_info->sequence_number;
          if (seq_diff == 1) {
            uint64_t delta = reception_time - clock_private_info->t2;
            clock_private_info->reception_interval = delta;
            debug(1," reception interval: %f", delta * 0.000001);

          }
        }
        */
    clock_private_info->sequence_number = ntohs(msg->header.sequenceId);
    clock_private_info->t2 = reception_time;

    // it turns out that we don't really need to send a Delay_Req
    // as a Follow_Up message always comes through

    // If we had hardware assisted network timing, then maybe
    // Even then, AP2 devices don't seem to send an accurate
    // Delay_Resp time -- it contains the same information as the Follow_Up

    clock_private_info->current_stage = sync_seen;
  }
}

void handle_follow_up(char *buf, ssize_t recv_len, clock_source *clock_info,
                      clock_source_private_data *clock_private_info, uint64_t reception_time,
                      pthread_mutex_t *shm_mutex) {
  struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;

  if ((clock_private_info->current_stage == sync_seen) &&
      (clock_private_info->sequence_number == ntohs(msg->header.sequenceId))) {

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
    // this result is called "t1" in the IEEE spec.
    // we already have "t2" and it seems as if we can't generate "t3"
    // and "t4", so use t1 - t2 as the clock-to-local offsets

    clock_private_info->current_stage = waiting_for_sync;

    // update the shared clock information
    uint64_t offset = preciseOriginTimestamp - clock_private_info->t2;

    // now, if there was a valid offset previously,
    // check if the offset should be clamped

    if ((clock_info->flags & (1 << clock_is_valid)) &&
        (clock_private_info->vacant_samples != MAX_TIMING_SAMPLES)) {

      /*
      if (clock_private_info->previous_estimated_offset != 0) {
          int64_t jitter = offset - clock_private_info->previous_estimated_offset;
          int64_t skew = 0;
              debug(1," reception interval is: %f", clock_private_info->reception_interval *
      0.000001); if (clock_private_info->reception_interval != 0) { uint64_t nominal_interval =
      125000000; // 125 ms skew = clock_private_info->reception_interval - nominal_interval; skew =
      skew / 2; offset = offset + skew; // try to compensate is a packet arrives too early or too
      late
          }

          int64_t compensated_jitter = offset - clock_private_info->previous_estimated_offset;
          debug(1," jitter: %f, skew: %f, compensated_jitter: %f.", jitter * 0.000001, skew *
      0.000001, compensated_jitter * 0.000001);
      }
      */

      /*
      // only clamp if in the timing peer list
        if ((clock_info->flags & (1 << clock_is_a_timing_peer)) != 0) {
            const int64_t clamp = 1 * 1000 * 1000; //
            int64_t jitter = offset - clock_private_info->previous_estimated_offset;
            if (jitter > clamp)
              offset = clock_private_info->previous_estimated_offset + clamp;
            else if (jitter < (-clamp))
              offset = clock_private_info->previous_estimated_offset - clamp;
            int64_t clamped_jitter = offset - clock_private_info->previous_estimated_offset;
            debug(1, "clock: %" PRIx64 ", jitter: %+f ms, clamped_jitter: %+f ms.",
      clock_info->clock_id, jitter * 0.000001, clamped_jitter * 0.000001);
        }
          // okay, so the offset may now have been clamped to be close to the estimated previous
      offset
      */
    }

    // update our sample information

    clock_private_info->samples[clock_private_info->next_sample_goes_here].local =
        clock_private_info->t2; // this is when the Sync message arrived.
    clock_private_info->samples[clock_private_info->next_sample_goes_here].local_to_remote_offset =
        offset;
    clock_private_info->samples[clock_private_info->next_sample_goes_here].sequence_number =
        clock_private_info->sequence_number;

    // if this is the very first...
    if (clock_private_info->vacant_samples == MAX_TIMING_SAMPLES) {
      clock_private_info->previous_offset = offset;
      clock_private_info->previous_estimated_offset = offset;
    }

    if (clock_private_info->vacant_samples > 0)
      clock_private_info->vacant_samples--;

    // okay, so now we have our samples, including the current one.

    // let's try to estimate when this Sync message _should_ have arrived.
    // this might allow us to detect a sample that is anomalously late or early
    // skewing the offset calculation.

    int sample_count = MAX_TIMING_SAMPLES - clock_private_info->vacant_samples;
    int64_t divergence;
    if (sample_count > 1) {
      int f;
      uint64_t ts = 0;
      for (f = 0; f < sample_count; f++) {
        uint64_t ti = clock_private_info->samples[f].local >> 8;
        uint16_t sequence_gap =
            clock_private_info->sequence_number - clock_private_info->samples[f].sequence_number;
        ti += (125000000 * (sequence_gap)) >> 8;
        // debug(1, "ti: %f, sequence_gap: %u, sample count: %u", ti, sequence_gap, sample_count);
        ts += ti;
      }
      ts = ts / sample_count;
      ts = ts << 8;
      // uint64_t estimated_t2 = (uint64_t)ts;
      divergence = clock_private_info->t2 - ts;
      // debug(1, "divergence is: %f ms. %d samples", divergence * 0.000001, sample_count);
    }

    // calculate averages

    // here we will correct the offset by adding the divergence to it

    offset = offset + divergence;

    const int64_t clamp = 1000 * 1000; // WAG
    int64_t jitter = offset - clock_private_info->previous_estimated_offset;
    if (jitter > clamp)
      offset = clock_private_info->previous_estimated_offset + clamp;
    else if (jitter < (-clamp))
      offset = clock_private_info->previous_estimated_offset - clamp;
    //    int64_t clamped_jitter = offset - clock_private_info->previous_estimated_offset;
    //     debug(1, "clock: %" PRIx64 ", jitter: %+f ms, clamped_jitter: %+f ms.",
    //     clock_info->clock_id,
    //           jitter * 0.000001, clamped_jitter * 0.000001);

    // okay, so the offset may now have been clamped to be close to the estimated previous offset

    uint64_t estimated_offset = offset;

    /*
        // here, calculate the average offset

        // int sample_count = MAX_TIMING_SAMPLES - clock_private_info->vacant_samples;

        if (sample_count > 1) {
          int e;
          long double offsets = 0;
          for (e = 0; e < sample_count; e++) {
            uint64_t ho = clock_private_info->samples[e].local_to_remote_offset;

            offsets = offsets + 1.0 * ho;
          }

          offsets = offsets / sample_count;
          estimated_offset = (uint64_t)offsets;
        }
    */

    int64_t estimated_variation = estimated_offset - clock_private_info->previous_estimated_offset;
    // debug(1, "clock: %" PRIx64 ", estimated_jitter: %+f ms, divergence: %+f.",
    // clock_info->clock_id,
    //      estimated_variation * 0.000001, divergence * 0.000001);

    clock_private_info->previous_estimated_offset = estimated_offset;

    int rc = pthread_mutex_lock(shm_mutex);
    if (rc != 0)
      warn("Can't acquire mutex to update a clock!");
    // update/set the clock_id

    clock_info->clock_id = packet_clock_id;
    clock_info->flags |= (1 << clock_is_valid);
    clock_info->local_time = clock_private_info->t2;
    clock_info->local_to_source_time_offset = estimated_offset;
    rc = pthread_mutex_unlock(shm_mutex);
    if (rc != 0)
      warn("Can't release mutex after updating a clock!");

    clock_private_info->next_sample_goes_here++;

    // if we have need to wrap.
    if (clock_private_info->next_sample_goes_here == MAX_TIMING_SAMPLES)
      clock_private_info->next_sample_goes_here = 0;

  } else {
    debug(3,
          "Follow_Up %u expecting to be in state sync_seen (%u). Stage error -- "
          "current state is %u, sequence %u. Ignoring it. %s",
          ntohs(msg->header.sequenceId), sync_seen, clock_private_info->current_stage,
          clock_private_info->sequence_number, clock_info->ip);
  }
}