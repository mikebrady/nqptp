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
#include <arpa/inet.h> // ntohl and ntohs
#include <string.h>    //strsep

#include <stdio.h> // snprintf

#include "debug.h"
#include "general-utilities.h"
#include "nqptp-message-handlers.h"
#include "nqptp-ptp-definitions.h"
#include "nqptp-utilities.h"

char hexcharbuffer[16384];

char *hex_string(void *buf, size_t buf_len) {
  char *tbuf = (char *)buf;
  char *obfp = hexcharbuffer;
  size_t obfc;
  for (obfc = 0; obfc < buf_len; obfc++) {
    snprintf(obfp, 3, "%02X", *tbuf);
    obfp += 2;
    tbuf = tbuf+1;
  };
  *obfp = 0;
  return hexcharbuffer;
}

void handle_control_port_messages(char *buf, ssize_t recv_len,
                                  clock_source_private_data *clock_private_info) {
  if (recv_len != -1) {
    buf[recv_len - 1] = 0; // make sure there's a null in it!
    debug(2, "New control port message: \"%s\".", buf);
    // we need to get the client shared memory interface name from the front
    char *ip_list = buf;
    char *smi_name = strsep(&ip_list, " ");
    char *command = NULL;
    if (smi_name != NULL) {
      int client_id = 0;
      if (ip_list != NULL)
        command = strsep(&ip_list, " ");
      debug(2,"Clear timing peer group.");
      // dirty experimental hack -- delete all the clocks
      int gc;
      for (gc = 0; gc < MAX_CLOCKS; gc++) {
        memset(&clock_private_info[gc], 0, sizeof(clock_source_private_data));
      }
      if ((command == NULL) || ((strcmp(command, "T") == 0) && (ip_list == NULL))) {
        
        // clear all the flags
        debug(2, "Stop monitoring.");
        int client_id = get_client_id(smi_name); // create the record if it doesn't exist
        if (client_id != -1) {
          /*
          int i;
          for (i = 0; i < MAX_CLOCKS; i++) {
            // e.g. (obsolete)
            clock_private_info[i].flags &= ~(1 << clock_is_master);
            clock_private_info[i].mastership_start_time = 0;
            clock_private_info[i].previous_offset_time = 0;

            // if a clock would now stop being a master everywhere
            // it should drop mastership history and do a sync when it becomes master again
            if ((clock_private_info[i].client_flags[client_id] & (1 << clock_is_master)) !=
                0) { // if clock[i] is master for this client's timing group
              int c;
              int this_clock_is_master_elsewhere = 0;
              for (c = 0; c < MAX_CLIENTS; c++) {
                if ((c != client_id) &&
                    ((clock_private_info[i].client_flags[c] & (1 << clock_is_master)) != 0))
                  this_clock_is_master_elsewhere = 1;
              }
              if (this_clock_is_master_elsewhere == 0) {
                clock_private_info[i].mastership_start_time = 0;
                clock_private_info[i].previous_offset_time = 0;
              }
            }
            clock_private_info[i].client_flags[client_id] = 0;
            
          }
          */
          update_master_clock_info(client_id, 0, NULL, 0, 0, 0); // it may have obsolete stuff in it
        }
        new_update_master_clock_info(0, NULL, 0, 0, 0); // it may have obsolete stuff in it
      } else {
        debug(2, "get or create new record for \"%s\".", smi_name);
        client_id = get_client_id(smi_name); // create the record if it doesn't exist
        if (client_id != -1) {
          if (strcmp(command, "T") == 0) {
            int i;
            for (i = 0; i < MAX_CLOCKS; i++) {
              clock_private_info[i].announcements_without_followups =
                  0; // to allow a possibly silent clock to be revisited when added to a timing
                     // peer list
              clock_private_info[i].follow_up_number = 0;
            }

            // take the first ip and make it the master, permanently
            
            
            if (ip_list != NULL) {
              char *new_ip = strsep(&ip_list, " ");
              // look for the IP in the list of clocks, and create an inert entry if not there
              if ((new_ip != NULL) && (new_ip[0] != 0)) {
                int t = find_clock_source_record(new_ip, clock_private_info);
                if (t == -1)
                  t = create_clock_source_record(new_ip, clock_private_info);
                if (t != -1) { // if the clock table is not full, show it's a timing peer
                  debug(2, "Monitor clock at %s.", new_ip);
                  clock_private_info[t].client_flags[client_id] |= (1 << clock_is_master);
                }
                // otherwise, drop it
              }
              
              
            }


/*
            while (ip_list != NULL) {
              char *new_ip = strsep(&ip_list, " ");
              // look for the IP in the list of clocks, and create an inert entry if not there
              if ((new_ip != NULL) && (new_ip[0] != 0)) {
                int t = find_clock_source_record(new_ip, clock_private_info);
                if (t == -1)
                  t = create_clock_source_record(new_ip, clock_private_info);
                if (t != -1) { // if the clock table is not full, show it's a timing peer
                  clock_private_info[t].client_flags[client_id] |= (1 << clock_is_a_timing_peer);
                }
                // otherwise, drop it
              }
            }
*/
          } else {
            warn("Unrecognised string on the control port.");
          }
        } else {
          warn("Could not find or create a record for SMI Interface \"%s\".", smi_name);
        }
      }
    } else {
      warn("SMI Interface Name not found on the control port.");
    }
  } else {
    warn("Bad packet on the control port.");
  }
}

void handle_announce(char *buf, ssize_t recv_len, clock_source_private_data *clock_private_info,
                     __attribute__((unused)) uint64_t reception_time) {
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

    if (clock_private_info->announcements_without_followups < 5) // don't keep going forever
      // a value of 4 means it's parked --
      // it has seen three, poked the clock and doesn't want to do any more.
      clock_private_info->announcements_without_followups++;

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

    clock_private_info->grandmasterIdentity = grandmaster_clock_id;
    clock_private_info->grandmasterPriority1 = msg->announce.grandmasterPriority1;
    clock_private_info->grandmasterQuality = clockQuality;
    clock_private_info->grandmasterClass = clockClass;
    clock_private_info->grandmasterAccuracy = clockAccuracy;
    clock_private_info->grandmasterVariance = offsetScaledLogVariance;
    clock_private_info->grandmasterPriority2 = msg->announce.grandmasterPriority2;
    clock_private_info->stepsRemoved = stepsRemoved;
    clock_private_info->clock_port_number = sourcePortID;
  }
}

void handle_sync(char *buf, ssize_t recv_len, clock_source_private_data *clock_private_info,
                 __attribute__((unused)) uint64_t reception_time) {
  if (clock_private_info->clock_id == 0) {
    debug(2, "Sync received before announcement -- discarded.");
  } else {
    if ((recv_len >= 0) && ((size_t)recv_len >= sizeof(struct ptp_sync_message))) {
        // debug_print_buffer(1, buf, recv_len);
        struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;

        // clang-format off
      
      // actually the precision timestamp needs to be corrected by the Follow_Up Correction_Field contents.
      // According to IEEE Std 802.1AS-2020, paragraph 11.4.4.2.1:
      /*
      The value of the preciseOriginTimestamp field is the sourceTime of the ClockMaster entity of the Grandmaster PTP Instance,
      when the associated Sync message was sent by that Grandmaster PTP Instance, with any fractional nanoseconds truncated (see 10.2.9).
      The sum of the correctionFields in the Follow_Up and associated Sync messages, added to the preciseOriginTimestamp field of the Follow_Up message,
      is the value of the synchronized time corresponding to the syncEventEgressTimestamp at the PTP Instance that sent the associated Sync message,
      including any fractional nanoseconds.
      */

        // clang-format on

        int64_t correction_field = ntoh64(msg->header.correctionField);

        if (correction_field != 0)
          debug(1, "Sync correction field is non-zero: %" PRId64 " ns.", correction_field);

        correction_field = correction_field / 65536; // might be signed
    } else {
      debug(1, "Sync message is too small to be valid.");
    }
  }
}

void handle_follow_up(char *buf, ssize_t recv_len, clock_source_private_data *clock_private_info,
                      uint64_t reception_time) {
  if (clock_private_info->clock_id == 0) {
    debug(2, "Follow_Up received before announcement -- discarded.");
  } else {
    clock_private_info->announcements_without_followups = 0;
    if ((recv_len >= 0) && ((size_t)recv_len >= sizeof(struct ptp_follow_up_message))) {
        // debug_print_buffer(1, buf, recv_len);
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

        if (clock_private_info->previous_preciseOriginTimestamp == preciseOriginTimestamp) {
          clock_private_info->identical_previous_preciseOriginTimestamp_count++;

          if (clock_private_info->identical_previous_preciseOriginTimestamp_count == 8 * 60) {
            int64_t duration_of_mastership =
                reception_time - clock_private_info->mastership_start_time;
            if (clock_private_info->mastership_start_time == 0)
              duration_of_mastership = 0;
            debug(2,
                  "Clock %" PRIx64
                  "'s grandmaster clock has stopped after %f seconds of mastership.",
                  clock_private_info->clock_id, 0.000000001 * duration_of_mastership);
            int64_t wait_limit = 62;
            wait_limit = wait_limit * 1000000000;
            // only try to restart a grandmaster clock on the clock itself.
            if ((duration_of_mastership <= wait_limit) && (clock_private_info->clock_id == clock_private_info->grandmasterIdentity)) {
              debug(1,
                    "Attempt to start a stopped clock %" PRIx64
                    ", at follow_up_number %u at IP %s.",
                    clock_private_info->clock_id, clock_private_info->follow_up_number,
                    clock_private_info->ip);
              send_awakening_announcement_sequence(
                  clock_private_info->clock_id, clock_private_info->ip, clock_private_info->family,
                  clock_private_info->grandmasterPriority1,
                  clock_private_info->grandmasterPriority2);
            }
          }
        } else {
          if (clock_private_info->identical_previous_preciseOriginTimestamp_count >= 8 * 60) {
            debug(2, "Clock %" PRIx64 "'s grandmaster clock has started again...",
                  clock_private_info->clock_id);
            clock_private_info->identical_previous_preciseOriginTimestamp_count = 0;
          }
        }

        clock_private_info->previous_preciseOriginTimestamp = preciseOriginTimestamp;

        // clang-format off
      
      // actually the precision timestamp needs to be corrected by the Follow_Up Correction_Field contents.
      // According to IEEE Std 802.1AS-2020, paragraph 11.4.4.2.1:
      /*
      The value of the preciseOriginTimestamp field is the sourceTime of the ClockMaster entity of the Grandmaster PTP Instance,
      when the associated Sync message was sent by that Grandmaster PTP Instance, with any fractional nanoseconds truncated (see 10.2.9).
      The sum of the correctionFields in the Follow_Up and associated Sync messages, added to the preciseOriginTimestamp field of the Follow_Up message,
      is the value of the synchronized time corresponding to the syncEventEgressTimestamp at the PTP Instance that sent the associated Sync message,
      including any fractional nanoseconds.
      */

        // clang-format on

        int64_t correction_field = ntoh64(msg->header.correctionField);

        // debug(1," Check ntoh64: in: %" PRIx64 ", out: %" PRIx64 ".", msg->header.correctionField,
        // correction_field);

        correction_field = correction_field / 65536; // might be signed
        uint64_t correctedPreciseOriginTimestamp = preciseOriginTimestamp + correction_field;

        if (clock_private_info->follow_up_number < 100)
          clock_private_info->follow_up_number++;

        // if (clock_private_info->announcements_without_followups < 4) // if we haven't signalled
        // already
        clock_private_info->announcements_without_followups = 0; // we've seen a followup

        debug(2, "FOLLOWUP from %" PRIx64 ", %s.", clock_private_info->clock_id,
              &clock_private_info->ip);
        uint64_t offset = correctedPreciseOriginTimestamp - reception_time;

        int64_t jitter = 0;

        int64_t time_since_previous_offset = 0;
        uint64_t smoothed_offset = offset;

        // This is a bit hacky.
        // Basically, the idea is that if the grandmaster has changed, then acceptance checking and
        // smoothing should start as it it's a new clock. This is because the
        // correctedPreciseOriginTimestamp, which is part of the data that is being smoothed, refers
        // to the grandmaster, so when the grandmaster changes any previous calculations are no
        // longer valid. The hacky bit is to signal this condition by zeroing the
        // previous_offset_time.
        if (clock_private_info->previous_offset_grandmaster !=
            clock_private_info->grandmasterIdentity)
          clock_private_info->previous_offset_time = 0;

        if (clock_private_info->previous_offset_time != 0) {
          time_since_previous_offset = reception_time - clock_private_info->previous_offset_time;
        }

        // Do acceptance checking and smoothing.

        // Positive changes in the offset are much more likely to be
        // legitimate, since they could only occur due to a shorter
        // propagation time or less of a delay sending or receiving the packet.
        // (Actually, this is not quite true --
        // it is possible that the remote clock could be adjusted forward
        // and this would increase the offset too.)
        // Anyway, when the clock is new, we give extra preferential weighting to
        // positive changes in the offset.

        // If the new offset is greater, by any amount, than the old offset,
        // or if it is less by up to 10 mS, accept it.
        // Otherwise, drop it if the last sample was fairly recent
        // If the last sample was long ago, take this as a discontinuity and
        // accept it as the start of a new period of mastership.

        // This seems to be quite stable

        if (clock_private_info->previous_offset_time != 0)
          jitter = offset - clock_private_info->previous_offset;

        // We take any positive or a limited negative jitter as a sync event in
        // a continuous synchronisation sequence.
        // This works well with PTP sources that sleep, as when they sleep
        // their clock stops. When they awaken, the offset from
        // the local clock to them must be smaller than before, triggering the
        // timing discontinuity below and allowing an immediate readjustment.

        // The full value of a positive offset jitter is accepted for a
        // number of follow_ups at the start.
        // After that, the weight of the jitter is reduced.
        // Follow-ups don't always come in at 125 ms intervals, especially after a discontinuity
        // Delays makes the offsets smaller than they should be, which is quickly
        // allowed for.
        
        int64_t mastership_time = reception_time - clock_private_info->mastership_start_time;
        if (clock_private_info->mastership_start_time == 0)
          mastership_time = 0;

        if ((clock_private_info->previous_offset_time != 0) && (jitter > -10000000)) {

          if (jitter < 0) {
            if (mastership_time < 1000000000) // at the beginning, if jitter is negative
              smoothed_offset = clock_private_info->previous_offset + jitter / 16;
            else
              smoothed_offset = clock_private_info->previous_offset + jitter / 64; // later, if jitter is negative
          } else if (mastership_time < 1000000000) { // at the beginning
            smoothed_offset =
                clock_private_info->previous_offset + jitter / 1; // at the beginning, if jitter is positive -- accept positive changes quickly
          } else {
            smoothed_offset = clock_private_info->previous_offset + jitter / 64; // later, if jitter is positive
          }
        } else {
          // allow samples to disappear for up to a second
          if ((time_since_previous_offset != 0) && (time_since_previous_offset < 1000000000) &&
              (jitter > -4000000000L)) {
            smoothed_offset = clock_private_info->previous_offset +
                              1; // if we have recent samples, forget the present sample...
          } else {
            if (clock_private_info->previous_offset_time == 0)
              debug(2, "Clock %" PRIx64 " record (re)starting at %s.", clock_private_info->clock_id,
                    clock_private_info->ip);
            else
              debug(2,
                    "Timing discontinuity on clock %" PRIx64
                    " at %s: time_since_previous_offset: %.3f seconds.",
                    clock_private_info->clock_id, clock_private_info->ip,
                    0.000000001 * time_since_previous_offset);
            smoothed_offset = offset;
            // clock_private_info->follow_up_number = 0;
            clock_private_info->mastership_start_time =
                reception_time; // mastership is reset to this time...
          }
        }

        clock_private_info->previous_offset_grandmaster = clock_private_info->grandmasterIdentity;
        clock_private_info->previous_offset = smoothed_offset;
        clock_private_info->previous_offset_time = reception_time;

        int temp_client_id;
        for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
          if ((clock_private_info->client_flags[temp_client_id] & (1 << clock_is_master)) != 0) {
            // recalculate mastership_time because it might have been zeroed.
            mastership_time = reception_time - clock_private_info->mastership_start_time;
            if (clock_private_info->mastership_start_time == 0)
              mastership_time = 0;
            if (mastership_time > 200000000) {
              int64_t delta = smoothed_offset - offset;
              debug(2,
                    "Clock %" PRIx64 ", grandmaster %" PRIx64 ". Offset: %" PRIx64
                    ", smoothed offset: %" PRIx64 ". Smoothed Offset - Offset: %10.3f. Raw Precise Origin Timestamp: %" PRIx64
                    ". Time since previous offset: %8.3f milliseconds. ID: %5u, Follow_Up Number: "
                    "%u. Source: %s",
                    clock_private_info->clock_id, clock_private_info->grandmasterIdentity, offset,
                    smoothed_offset, 0.000001 * delta, preciseOriginTimestamp, 0.000001 * time_since_previous_offset,
                    ntohs(msg->header.sequenceId), clock_private_info->follow_up_number,
                    clock_private_info->ip);

              debug(2, "clock_is_master -- updating master clock info for client \"%s\"",
                    get_client_name(temp_client_id));
              update_master_clock_info(temp_client_id, clock_private_info->grandmasterIdentity,
                                       (const char *)&clock_private_info->ip, reception_time,
                                       smoothed_offset, clock_private_info->mastership_start_time);
            }
          }
        }

        int64_t delta = smoothed_offset - offset;
        debug(2,
              "Clock %" PRIx64 ", grandmaster %" PRIx64 ". Offset: %" PRIx64
              ", smoothed offset: %" PRIx64 ". Smoothed Offset - Offset: %10.3f. Raw Precise Origin Timestamp: %" PRIx64
              ". Time since previous offset: %8.3f milliseconds. ID: %5u, Follow_Up Number: "
              "%u. Source: %s",
              clock_private_info->clock_id, clock_private_info->grandmasterIdentity, offset,
              smoothed_offset, 0.000001 * delta, preciseOriginTimestamp, 0.000001 * time_since_previous_offset,
              ntohs(msg->header.sequenceId), clock_private_info->follow_up_number,
              clock_private_info->ip);

        new_update_master_clock_info(clock_private_info->grandmasterIdentity,
                         (const char *)&clock_private_info->ip, reception_time,
                         smoothed_offset, clock_private_info->mastership_start_time);
        
        // now do some quick calculations on the possible "Universal Time"
        // debug_print_buffer(1, "", buf, recv_len);
        uint8_t *tlv = (uint8_t *)&msg->follow_up.tlvs[0];
        uint8_t *lastGmPhaseChange = tlv + 16;
        uint64_t lpt = nctoh64(lastGmPhaseChange + 4);
        uint64_t last_tlv_clock = nctoh64((uint8_t *)buf + 86);
        uint64_t huh = offset - lpt;
        debug_print_buffer(2, buf, (size_t) recv_len);
        debug(2, "%" PRIx64 ", %" PRIx64 ", %s, Origin: %016" PRIx64 ", LPT: %016" PRIx64 ", Offset: %016" PRIx64 ", Universal Offset: %016" PRIx64 ", packet length: %u.", clock_private_info->clock_id, last_tlv_clock,  hex_string(lastGmPhaseChange,12), preciseOriginTimestamp, lpt, offset, huh, recv_len);
        // debug(1,"Clock: %" PRIx64 ", UT: %016" PRIx64 ", correctedPOT: %016" PRIx64 ", part of lastGMPhaseChange: %016" PRIx64 ".", packet_clock_id, correctedPOT - lpt, correctedPOT, lpt);

    } else {
      debug(1, "Follow_Up message is too small to be valid.");
    }
  }
}
