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

#include "nqptp-clock-sources.h"
#include "debug.h"
#include "general-utilities.h"
#include "nqptp-ptp-definitions.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/types.h>

#ifdef CONFIG_FOR_FREEBSD
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

clock_source_private_data clocks_private[MAX_CLOCKS];

int find_clock_source_record(char *sender_string, clock_source_private_data *clocks_private_info) {
  // return the index of the clock in the clock information arrays or -1
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if ((clocks_private_info[i].in_use != 0) &&
        (strcasecmp(sender_string, (const char *)&clocks_private_info[i].ip) == 0))
      found = 1;
    else
      i++;
  }
  if (found == 1)
    response = i;
  return response;
}

int create_clock_source_record(char *sender_string,
                               clock_source_private_data *clocks_private_info) {
  // sometimes, the mutex will already be locked
  // return the index of a clock entry in the clock information arrays or -1 if full
  // initialise the entries in the shared and private arrays
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if (clocks_private_info[i].in_use == 0)
      found = 1;
    else
      i++;
  }

  if (found == 1) {
    response = i;
    memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
    strncpy((char *)&clocks_private_info[i].ip, sender_string,
            FIELD_SIZEOF(clock_source_private_data, ip) - 1);
    clocks_private_info[i].vacant_samples = MAX_TIMING_SAMPLES;
    clocks_private_info[i].in_use = 1;
    debug(2, "create record for ip: %s.", &clocks_private_info[i].ip);
  } else {
    die("Clock tables full!");
  }
  return response;
}

void manage_clock_sources(uint64_t reception_time, clock_source_private_data *clocks_private_info) {
  debug(3, "manage_clock_sources");
  int i;

  // do a garbage collect for clock records no longer in use
  for (i = 0; i < MAX_CLOCKS; i++) {
    // only if its in use and not a timing peer... don't need a mutex to check
    if ((clocks_private_info[i].in_use != 0) &&
        ((clocks_private_info[i].flags & (1 << clock_is_a_timing_peer)) == 0)) {
      int64_t time_since_last_use = reception_time - clocks_private_info[i].time_of_last_use;
      // using a sync timeout to determine when to drop the record...
      // the following give the sync receipt time in whole seconds
      // depending on the aPTPinitialLogSyncInterval and the aPTPsyncReceiptTimeout
      int64_t syncTimeout = (1 << (32 + aPTPinitialLogSyncInterval));
      syncTimeout = syncTimeout * aPTPsyncReceiptTimeout;
      syncTimeout = syncTimeout >> 32;
      // seconds to nanoseconds
      syncTimeout = syncTimeout * 1000000000;
      if (time_since_last_use > syncTimeout) {
        uint32_t old_flags = clocks_private_info[i].flags;
        debug(2, "delete record for: %s.", &clocks_private_info[i].ip);
        memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
        if (old_flags != 0)
          update_master();
      }
    }
  }
}

// check all the entries in the clock array and mark all those that
// belong to ourselves

void update_clock_self_identifications(clock_source_private_data *clocks_private_info) {
  // first, turn off all the self-id flags
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    clocks_private_info[i].is_one_of_ours = 0;
  }

  struct ifaddrs *ifap, *ifa;
  void *addr = NULL;
  short family;
  int response = getifaddrs(&ifap);
  if (response == 0) {
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      struct sockaddr *my_ifa_addr = ifa->ifa_addr;
      if (my_ifa_addr) {
        family = my_ifa_addr->sa_family;
#ifdef AF_INET6
        if (family == AF_INET6) {
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)my_ifa_addr;
          addr = &(sa6->sin6_addr);
        }
#endif
        if (family == AF_INET) {
          struct sockaddr_in *sa4 = (struct sockaddr_in *)my_ifa_addr;
          addr = &(sa4->sin_addr);
        }
        char ip_string[64];
        memset(ip_string, 0, sizeof(ip_string));
        if (addr != NULL)
          inet_ntop(family, addr, ip_string, sizeof(ip_string));
        if (strlen(ip_string) != 0) {
          // now set the is_one_of_ours flag of any clock with this ip
          for (i = 0; i < MAX_CLOCKS; i++) {
            if (strcasecmp(ip_string, clocks_private_info[i].ip) == 0) {
              debug(2, "found an entry for one of our clocks");
              clocks_private_info[i].is_one_of_ours = 1;
            }
          }
        }
      } else {
        debug(1, "NULL ifa->ifa_addr. Probably harmless.");
      }
    }
    freeifaddrs(ifap);
  } else {
    debug(1, "getifaddrs error - %s.", strerror(errno));
  }
}

void debug_log_nqptp_status(int level) {
  int records_in_use = 0;
  int i;
  for (i = 0; i < MAX_CLOCKS; i++)
    if (clocks_private[i].in_use != 0)
      records_in_use++;
  if (records_in_use > 0) {
    debug(level, "");
    debug(level, "Current NQPTP Status:");
    uint32_t peer_mask = (1 << clock_is_a_timing_peer);
    uint32_t peer_clock_mask = peer_mask | (1 << clock_is_valid);
    uint32_t peer_master_mask = peer_clock_mask | (1 << clock_is_master);
    uint32_t peer_becoming_master_mask = peer_clock_mask | (1 << clock_is_becoming_master);
    uint32_t non_peer_clock_mask = (1 << clock_is_valid);
    uint32_t non_peer_master_mask = non_peer_clock_mask | (1 << clock_is_master);
    for (i = 0; i < MAX_CLOCKS; i++) {
      if (clocks_private[i].in_use != 0) {
        if ((clocks_private[i].flags & peer_master_mask) == peer_master_mask) {
          debug(level, "  Peer Master:            %" PRIx64 "  %s.", clocks_private[i].clock_id,
                clocks_private[i].ip);
        } else if ((clocks_private[i].flags & peer_becoming_master_mask) ==
                   peer_becoming_master_mask) {
          debug(level, "  Peer Becoming Master:   %" PRIx64 "  %s.", clocks_private[i].clock_id,
                clocks_private[i].ip);
        } else if ((clocks_private[i].flags & peer_clock_mask) == peer_clock_mask) {
          debug(level, "  Peer Clock:             %" PRIx64 "  %s.", clocks_private[i].clock_id,
                clocks_private[i].ip);
        } else if ((clocks_private[i].flags & peer_mask) == peer_mask) {
          debug(level, "  Peer:                                     %s.", clocks_private[i].ip);
        } else if ((clocks_private[i].flags & non_peer_master_mask) == non_peer_master_mask) {
          debug(level, "  Non Peer Master:        %" PRIx64 "  %s.", clocks_private[i].clock_id,
                clocks_private[i].ip);
        } else if ((clocks_private[i].flags & non_peer_clock_mask) == non_peer_clock_mask) {
          debug(level, "  Non Peer Clock:         %16" PRIx64 "  %s.", clocks_private[i].clock_id,
                clocks_private[i].ip);
        } else {
          debug(level, "  Non Peer Record:                          %s.", clocks_private[i].ip);
        }
      }
    }
  }
}

int uint32_cmp(uint32_t a, uint32_t b, const char *cause) {
  // returns -1 if a is less than b, 0 if a = b, +1 if a is greater than b
  if (a == b) {
    return 0;
  } else {
    debug(2, "Best Master Clock algorithm deciding factor: %s. Values: %u, %u.", cause, a, b);
    if (a < b)
      return -1;
    else
      return 1;
  }
}

int uint64_cmp(uint64_t a, uint64_t b, const char *cause) {
  // returns -1 if a is less than b, 0 if a = b, +1 if a is greater than b
  if (a == b) {
    return 0;
  } else {
    debug(2, "Best Master Clock algorithm deciding factor: %s. Values: %" PRIx64 ", %" PRIx64 ".",
          cause, a, b);
    if (a < b)
      return -1;
    else
      return 1;
  }
}

void update_master() {

  // This implements the IEEE 1588-2008 best master clock algorithm.

  // However, since nqptp is not a ptp clock, some of it doesn't apply.
  // Specifically, the Identity of Receiver stuff doesn't apply, since the
  // program is merely monitoring Announce message data and isn't a PTP clock itself
  // and thus does not have any kind or receiver identity itself.

  // Clock information coming from the same clock over IPv4 and IPv6 should have different
  // port numbers.

  // Figure 28 can be therefore be simplified considerably:

  // Since nqptp can not be a receiver, and since nqptp can not originate a clock
  // (and anyway nqptp filters out packets coming from self)
  // we can do a single comparison of stepsRemoved and pick the shorter, if any.

  // Figure 28 reduces to checking steps removed and then, if necessary, checking identities.
  // If we see two identical sets of information, it is an error,
  // but we leave things as they are.
  int old_master = -1;
  // find the current master clock if there is one and turn off all mastership
  int i;
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clocks_private[i].flags & (1 << clock_is_master)) != 0)
      if (old_master == -1)
        old_master = i;                                          // find old master
    clocks_private[i].flags &= ~(1 << clock_is_master);          // turn them all off
    clocks_private[i].flags &= ~(1 << clock_is_becoming_master); // turn them all off
  }

  int best_so_far = -1;
  int timing_peer_count = 0;
  uint32_t acceptance_mask =
      (1 << clock_is_qualified) | (1 << clock_is_a_timing_peer) | (1 << clock_is_valid);
  for (i = 0; i < MAX_CLOCKS; i++) {
    if ((clocks_private[i].flags & acceptance_mask) == acceptance_mask) {
      // found a possible clock candidate
      timing_peer_count++;
      int outcome;
      if (best_so_far == -1) {
        best_so_far = i;
      } else {
        // Do the data set comparison detailed in Figure 27 and Figure 28 on pp89-90
        if (clocks_private[i].grandmasterIdentity ==
            clocks_private[best_so_far].grandmasterIdentity) {
          // Do the relevant part of Figure 28:
          outcome = uint32_cmp(clocks_private[i].stepsRemoved,
                               clocks_private[best_so_far].stepsRemoved, "steps removed");
          // we need to check the portIdentify, which is the clock_id and the clock_port_number
          if (outcome == 0)
            outcome = uint64_cmp(clocks_private[i].clock_id, clocks_private[best_so_far].clock_id,
                                 "clock id");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].clock_port_number,
                           clocks_private[best_so_far].clock_port_number, "clock port number");
          if (outcome == 0) {
            debug(1,
                  "Best Master Clock algorithm: two separate but identical potential clock "
                  "masters: %" PRIx64 ".",
                  clocks_private[best_so_far].clock_id);
          }

        } else {
          outcome =
              uint32_cmp(clocks_private[i].grandmasterPriority1,
                         clocks_private[best_so_far].grandmasterPriority1, "grandmasterPriority1");
          if (outcome == 0)
            outcome = uint32_cmp(clocks_private[i].grandmasterClass,
                                 clocks_private[best_so_far].grandmasterClass, "grandmasterClass");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].grandmasterAccuracy,
                           clocks_private[best_so_far].grandmasterAccuracy, "grandmasterAccuracy");
          if (outcome == 0)
            outcome =
                uint32_cmp(clocks_private[i].grandmasterVariance,
                           clocks_private[best_so_far].grandmasterVariance, "grandmasterVariance");
          if (outcome == 0)
            outcome = uint32_cmp(clocks_private[i].grandmasterPriority2,
                                 clocks_private[best_so_far].grandmasterPriority2,
                                 "grandmasterPriority2");
          if (outcome == 0)
            // this can't fail, as it's a condition of entering this section that they are different
            outcome =
                uint64_cmp(clocks_private[i].grandmasterIdentity,
                           clocks_private[best_so_far].grandmasterIdentity, "grandmasterIdentity");
        }
        if (outcome == -1)
          best_so_far = i;
      }
    }
  }
  if (best_so_far == -1) {
    // no master clock
    if (old_master != -1) {
      // but there was a master clock, so remove it
      debug(2, "Remove master clock.");
      update_master_clock_info(0, NULL, 0, 0, 0);
    }
    if (timing_peer_count == 0)
      debug(2, "No timing peer list found");
    else
      debug(1, "No master clock not found!");
  } else {
    // we found a master clock

    if (old_master != best_so_far) {
      // if the naster is a new one
      clocks_private[best_so_far].flags |= (1 << clock_is_becoming_master);
    } else {
      // if its the same one as before
      clocks_private[best_so_far].flags |= (1 << clock_is_master);
    }
  }
  debug_log_nqptp_status(1);
}
