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
    debug(2, "New control port message: \"%s\".", buf);
    // we need to get the client shared memory interface name from the front
    char *ip_list = buf;
    char *smi_name = strsep(&ip_list, " ");
    char *command = NULL;
    if (smi_name != NULL) {
      int client_id = 0;
      if (ip_list != NULL)
        command = strsep(&ip_list, " ");
      if ((command == NULL) || ((strcmp(command, "T") == 0) && (ip_list == NULL))) {
        // clear all the flags, but only if the client exists
        client_id = get_client_id(smi_name); // create the record if it doesn't exist
        if (client_id != -1) {
          // turn off all is_timing_peer flags
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
        }
      } else {
        debug(2,"get or create new record for \"%s\".",smi_name);
        client_id = get_client_id(smi_name); // create the record if it doesn't exist
        if (client_id != -1) {
          if (strcmp(command, "T") == 0) {
            // turn off all is_timing_peer flags
            int i;
            for (i = 0; i < MAX_CLOCKS; i++) {
              clock_private_info[i].flags &=
                  ~(1 << clock_is_a_timing_peer); // turn off peer flag (but not the master flag!)
              clock_private_info[i].client_flags[client_id] &=
                  ~(1 << clock_is_a_timing_peer); // turn off peer flag (but not the master flag!)
              clock_private_info[i].announcements_without_followups =
                  0; // to allow a possibly silent clock to be revisited when added to a timing
                     // peer list
              clock_private_info[i].follow_up_number = 0;
            }
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

            // now find and mark the best clock in the timing peer list as the master
            update_master(client_id);

            debug(2, "Timing group start");
            for (i = 0; i < MAX_CLOCKS; i++) {
              if ((clock_private_info[i].client_flags[client_id] & (1 << clock_is_a_timing_peer)) !=
                  0)
                debug(2, "%s.", &clock_private_info[i].ip);
            }
            debug(2, "Timing group end");
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
                     uint64_t reception_time) {
  // only process Announce messages that do not come from self
  if ((clock_private_info->flags & (1 << clock_is_one_of_ours)) == 0) {
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
          // check/update the mastership of any clients that might be affected
          int temp_client_id;
          for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
            if ((clock_private_info->client_flags[temp_client_id] &
                 (1 << clock_is_a_timing_peer)) != 0) {
              debug(2,
                    "best_clock_update_needed because %" PRIx64
                    " on ip %s has changed -- updating clock mastership for client \"%s\"",
                    clock_private_info->clock_id, clock_private_info->ip,
                    get_client_name(temp_client_id));
              update_master(temp_client_id);
            }
          }
        }
      } else {
        if ((clock_private_info->flags & (1 << clock_is_qualified)) !=
            0) // if it was qualified, but now isn't
          debug(1,
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

  if (clock_private_info->announcements_without_followups < 4) // if we haven't signalled already
    clock_private_info->announcements_without_followups = 0;   // we've seen a followup

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

  int clock_is_becoming_master_somewhere = 0;
  {
    int temp_client_id;
    for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
      if ((clock_private_info->client_flags[temp_client_id] & (1 << clock_is_becoming_master)) !=
          0) {
        clock_is_becoming_master_somewhere = 1;
      }
    }
  }
  if ((clock_private_info->flags & (1 << clock_is_becoming_master)) != 0)
    clock_is_becoming_master_somewhere = 1;

  if (clock_is_becoming_master_somewhere != 0) {
    // we now definitely have at least one sample since a request was made to
    // designate this clock a master, so we assume it is legitimate. That is, we assume
    // that the clock originator knows that it a clock master by now.
    clock_private_info->mastership_start_time = clock_private_info->local_time;

    // designate the clock as master wherever is was becoming a master
    {
      int temp_client_id;
      for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
        if ((clock_private_info->client_flags[temp_client_id] & (1 << clock_is_becoming_master)) !=
            0) {
          debug(2,
                "clock_is_becoming_master %" PRIx64
                " at %s -- changing to clock_is_master for client \"%s\"",
                clock_private_info->clock_id, clock_private_info->ip,
                get_client_name(temp_client_id));
          clock_private_info->client_flags[temp_client_id] &= ~(1 << clock_is_becoming_master);
          clock_private_info->client_flags[temp_client_id] |= (1 << clock_is_master);
        }
      }
    }

    clock_private_info->previous_offset_time = 0;
    debug_log_nqptp_status(2);
  } else if ((clock_private_info->previous_offset_time != 0) &&
             (time_since_previous_offset < 300000000000)) {
    // i.e. if it's not becoming a master and there has been a previous follow_up
    int64_t time_since_last_sync = reception_time - clock_private_info->last_sync_time;
    int64_t sync_timeout = 300000000000; // nanoseconds
    if (clock_private_info->last_sync_time == 0)
      debug(2, "Never synced.");
    else
      debug(2, "Sync interval: %f seconds.", 0.000000001 * time_since_last_sync);
    if ((clock_private_info->last_sync_time != 0) && (time_since_last_sync < sync_timeout)) {

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
      int clock_is_a_master_somewhere = 0;
      int temp_client_id;
      for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
        if ((clock_private_info->client_flags[temp_client_id] & (1 << clock_is_master)) != 0) {
          clock_is_a_master_somewhere = 1;
        }
      }

      if ((clock_is_a_master_somewhere != 0) && (clock_private_info->last_sync_time == 0))
        debug(2, "Synchronising master clock %" PRIx64 " at %s.", clock_private_info->clock_id,
              clock_private_info->ip);
      if ((clock_is_a_master_somewhere != 0) && (clock_private_info->last_sync_time != 0))
        debug(1, "Resynchronising master clock %" PRIx64 " at %s.", clock_private_info->clock_id,
              clock_private_info->ip);
      // leave the offset as it was coming in and take it as a sync time
      clock_private_info->last_sync_time = reception_time;
      clock_private_info->mastership_start_time =
          reception_time; // mastership is reset to this time...
      clock_private_info->previous_offset_time = 0;
    }
  } else {
    clock_private_info->last_sync_time = reception_time;
    if (time_since_previous_offset >= 300000000000) {
      debug(1, "Long interval: %f seconds since previous follow_up",
            time_since_previous_offset * 1E-9);
      clock_private_info->mastership_start_time =
          reception_time; // mastership is reset to this time...
      clock_private_info->previous_offset_time = 0;
    }
  }

  clock_private_info->previous_offset = offset;
  clock_private_info->previous_offset_time = reception_time;

  int temp_client_id;
  for (temp_client_id = 0; temp_client_id < MAX_CLIENTS; temp_client_id++) {
    if ((clock_private_info->client_flags[temp_client_id] & (1 << clock_is_master)) != 0) {
      debug(2, "clock_is_master -- updating master clock info for client \"%s\"",
            get_client_name(temp_client_id));
      update_master_clock_info(temp_client_id, clock_private_info->clock_id,
                               (const char *)&clock_private_info->ip, reception_time, offset,
                               clock_private_info->mastership_start_time);
    }
  }
}
