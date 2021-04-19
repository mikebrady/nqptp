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
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "general-utilities.h"
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"

void update_master_old(clock_source_private_data *clock_private_info) {
  int old_master = -1;
  // find the current master clock if there is one and turn off all mastership
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clock_private_info[i].flags & (1 << clock_is_master)) != 0)
      if (old_master == -1)
        old_master = i;                                     // find old master
    clock_private_info[i].flags &= ~(1 << clock_is_master); // turn them all off
  }

  int best_so_far = -1;
  int timing_peer_count = 0;
  uint32_t acceptance_mask =
      (1 << clock_is_valid) | (1 << clock_is_qualified) | (1 << clock_is_a_timing_peer);
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clock_private_info[i].flags & acceptance_mask) == acceptance_mask) {
      // found a possible clock candidate
      timing_peer_count++;
      if (best_so_far == -1) {
        best_so_far = i;
      } else {
        // do the data set comparison detailed in Figure 27 and Figure 28 on pp89-90
        if (clock_private_info[i].grandmasterIdentity ==
            clock_private_info[best_so_far].grandmasterIdentity) {
          // should implement Figure 28 here
        } else if (clock_private_info[i].grandmasterPriority1 <
                   clock_private_info[best_so_far].grandmasterPriority1) {
          best_so_far = i;
        } else if (clock_private_info[i].grandmasterClass <
                   clock_private_info[best_so_far].grandmasterClass) {
          best_so_far = i;
        } else if (clock_private_info[i].grandmasterAccuracy <
                   clock_private_info[best_so_far].grandmasterAccuracy) {
          best_so_far = i;
        } else if (clock_private_info[i].grandmasterVariance <
                   clock_private_info[best_so_far].grandmasterVariance) {
          best_so_far = i;
        } else if (clock_private_info[i].grandmasterPriority2 <
                   clock_private_info[best_so_far].grandmasterPriority2) {
          best_so_far = i;
        } else if (clock_private_info[i].grandmasterIdentity <
                   clock_private_info[best_so_far].grandmasterIdentity) {
          best_so_far = i;
        }
      }
    }
  }
  if (best_so_far != -1) {
    // we found a master clock
    clock_private_info[best_so_far].flags |= (1 << clock_is_master);
    // master_clock_index = best_so_far;
    if (old_master != best_so_far) {
      update_master_clock_info(clock_private_info[best_so_far].clock_id,
                               clock_private_info[best_so_far].local_time,
                               clock_private_info[best_so_far].local_to_source_time_offset);
    }
  } else {
    if (timing_peer_count == 0)
      debug(2, "No timing peer list found");
    else
      debug(1, "No master clock not found!");
  }

  // check
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clock_private_info[i].flags & (1 << clock_is_master)) != 0)
      debug(2, "leaving with %d as master", i);
  }
}

void update_master() { update_master_old(clocks_private); }

void handle_control_port_messages(char *buf, ssize_t recv_len,
                                  clock_source_private_data *clock_private_info) {
  if (recv_len != -1) {
    buf[recv_len - 1] = 0; // make sure there's a null in it!
    debug(2, "Received a new timing peer list message: \"%s\".", buf);
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

          // if it is just about to become a timing peer, reset its sample count
          // since we don't know what was going on beforehand
          clock_private_info[t].mm_count = 0;
          clock_private_info[t].vacant_samples = MAX_TIMING_SAMPLES;
          clock_private_info[t].next_sample_goes_here = 0;

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

void handle_sync(char *buf, __attribute__((unused)) ssize_t recv_len,
                 clock_source_private_data *clock_private_info, uint64_t reception_time,
                 SOCKADDR *from_sock_addr, int socket_number) {
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

    // send a delay request message
    {
      struct ptp_delay_req_message m;
      memset(&m, 0, sizeof(m));
      m.header.transportSpecificAndMessageID = 0x11; // Table 19, pp 125, 1 byte field
      m.header.reservedAndVersionPTP = 0x02;         // 1 byte field
      m.header.messageLength = htons(44);
      m.header.flags = htons(0x608);
      m.header.sourcePortID = htons(1);
      m.header.controlOtherMessage = 5; // 1 byte field
      m.header.sequenceId = htons(clock_private_info->sequence_number);
      uint64_t sid = get_self_clock_id();
      memcpy(&m.header.clockIdentity, &sid, sizeof(uint64_t));
      struct msghdr header;
      struct iovec io;
      memset(&header, 0, sizeof(header));
      memset(&io, 0, sizeof(io));
      header.msg_name = from_sock_addr;
      header.msg_namelen = sizeof(SOCKADDR);
      header.msg_iov = &io;
      header.msg_iov->iov_base = &m;
      header.msg_iov->iov_len = sizeof(m);
      header.msg_iovlen = 1;
      clock_private_info->t3 = get_time_now(); // in case nothing better works
      if ((sendmsg(socket_number, &header, 0)) == -1) {
        // debug(1, "Error in sendmsg [errno = %d] to socket %d.", errno, socket_number);
        // debug_print_buffer(1,(char *)&m, sizeof(m));
      } else {
        // debug(1, "Success in sendmsg to socket %d.", socket_number);
      }
    }
  }
}

void handle_follow_up(char *buf, __attribute__((unused)) ssize_t recv_len,
                      clock_source_private_data *clock_private_info,
                      __attribute__((unused)) uint64_t reception_time) {
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

    clock_private_info->t1 = preciseOriginTimestamp;

    // we already have "t2" and it seems as if we can't generate "t3"
    // and "t4", so use t1 - t2 as the clock-to-local offsets

    clock_private_info->current_stage = follow_up_seen;

  } else {
    debug(3,
          "Follow_Up %u expecting to be in state sync_seen (%u). Stage error -- "
          "current state is %u, sequence %u. Ignoring it. %s",
          ntohs(msg->header.sequenceId), sync_seen, clock_private_info->current_stage,
          clock_private_info->sequence_number, clock_private_info->ip);
  }
}

void handle_delay_resp(char *buf, __attribute__((unused)) ssize_t recv_len,
                       clock_source_private_data *clock_private_info,
                       __attribute__((unused)) uint64_t reception_time) {
  struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;

  if ((clock_private_info->current_stage == follow_up_seen) &&
      (clock_private_info->sequence_number == ntohs(msg->header.sequenceId))) {

    uint64_t packet_clock_id = nctohl(&msg->header.clockIdentity[0]);
    uint64_t packet_clock_id_low = nctohl(&msg->header.clockIdentity[4]);
    packet_clock_id = packet_clock_id << 32;
    packet_clock_id = packet_clock_id + packet_clock_id_low;

    uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
    uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
    uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
    uint64_t receiveTimestamp = seconds_hi;
    receiveTimestamp = receiveTimestamp << 32;
    receiveTimestamp = receiveTimestamp + seconds_low;
    receiveTimestamp = receiveTimestamp * 1000000000L;
    receiveTimestamp = receiveTimestamp + nanoseconds;

    // this is t4 in the IEEE doc and should be close to t1
    // on some systems, it is identical to t1.

    // uint64_t delay_req_turnaround_time = reception_time - clock_private_info->t3;
    uint64_t t4t1diff = receiveTimestamp - clock_private_info->t1;
    // uint64_t t3t2diff = clock_private_info->t3 - clock_private_info->t2;
    // debug(1,"t4t1diff: %f, delay_req_turnaround_time: %f, t3t2diff: %f.", t4t1diff * 0.000000001,
    // delay_req_turnaround_time * 0.000000001, t3t2diff * 0.000000001);

    if (t4t1diff < 20000000) {
      // update the shared clock information
      uint64_t offset = clock_private_info->t1 - clock_private_info->t2;

      // update our sample information

      clock_private_info->samples[clock_private_info->next_sample_goes_here].local =
          clock_private_info->t2; // this is when the Sync message arrived.
      clock_private_info->samples[clock_private_info->next_sample_goes_here]
          .local_to_remote_offset = offset;
      clock_private_info->samples[clock_private_info->next_sample_goes_here].sequence_number =
          clock_private_info->sequence_number;

      // if this is the very first...
      if (clock_private_info->vacant_samples == MAX_TIMING_SAMPLES) {
        clock_private_info->previous_offset = offset;
        clock_private_info->previous_estimated_offset = offset;
      }

      if (clock_private_info->vacant_samples > 0)
        clock_private_info->vacant_samples--;

      // do the mickey mouse averaging
      if (clock_private_info->mm_count == 0) {
        clock_private_info->mm_average = offset;
        clock_private_info->mm_count = 1;
      } else {
        if (clock_private_info->mm_count < 5000)
          clock_private_info->mm_count++;
        clock_private_info->mm_average =
            (clock_private_info->mm_count - 1) *
            (clock_private_info->mm_average / clock_private_info->mm_count);
        clock_private_info->mm_average =
            clock_private_info->mm_average + (1.0 * offset) / clock_private_info->mm_count;
      }
      uint64_t estimated_offset = (uint64_t)clock_private_info->mm_average;

      /*
            // do real averaging

            int sample_count = MAX_TIMING_SAMPLES - clock_private_info->vacant_samples;
            int64_t divergence = 0;
            uint64_t estimated_offset = offset;

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

      clock_private_info->previous_estimated_offset = estimated_offset;

      clock_private_info->clock_id = packet_clock_id;
      clock_private_info->flags |= (1 << clock_is_valid);
      clock_private_info->local_time = clock_private_info->t2;
      clock_private_info->local_to_source_time_offset = estimated_offset;

      // debug(1,"mm_average: %" PRIx64 ", estimated_offset: %" PRIx64 ".", mm_average_int,
      // estimated_offset);
      if ((clock_private_info->flags & (1 << clock_is_master)) != 0) {
        update_master_clock_info(clock_private_info->clock_id, clock_private_info->local_time,
                                 clock_private_info->local_to_source_time_offset);
      }

      clock_private_info->next_sample_goes_here++;

      // if we have need to wrap.
      if (clock_private_info->next_sample_goes_here == MAX_TIMING_SAMPLES)
        clock_private_info->next_sample_goes_here = 0;
    } else {
      debug(2,
            "Dropping an apparently slow timing exchange with a disparity of %f milliseconds on "
            "clock: %" PRIx64 ".",
            t4t1diff * 0.000001, clock_private_info->clock_id);
    }

  } else {
    debug(3,
          "Delay_Resp %u expecting to be in state follow_up_seen (%u). Stage error -- "
          "current state is %u, sequence %u. Ignoring it. %s",
          ntohs(msg->header.sequenceId), follow_up_seen, clock_private_info->current_stage,
          clock_private_info->sequence_number, clock_private_info->ip);
  }
}