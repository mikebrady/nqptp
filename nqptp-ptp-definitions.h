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

#ifndef NQPTP_PTP_DEFINITIONS_H
#define NQPTP_PTP_DEFINITIONS_H

// References from the IEEE Document ISBN 978-0-7381-5400-8 STD95773.
// "IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and
// Control Systems" The IEEE Std 1588-2008 (Revision of IEEE Std 1588-2002)

// Table 19
enum messageType {
  Sync,
  Delay_Req,
  Pdelay_Req,
  Pdelay_Resp,
  Reserved_4,
  Reserved_5,
  Reserved_6,
  Reserved_7,
  Follow_Up,
  Delay_Resp,
  Pdelay_Resp_Follow_Up,
  Announce,
  Signaling,
  Management,
  Reserved_E,
  Reserved_F
};

 // this is the Common Message Header
  struct __attribute__((__packed__)) ptp_common_message_header {
    uint8_t transportSpecificAndMessageID; // 0x11
    uint8_t reservedAndVersionPTP;         // 0x02
    uint16_t messageLength;
    uint8_t domainNumber;        // 0
    uint8_t reserved_b;          // 0
    uint16_t flags;              // 0x0608
    uint64_t correctionField;    // 0
    uint32_t reserved_l;         // 0
    uint8_t clockIdentity[8];    // MAC
    uint16_t sourcePortID;       // 1
    uint16_t sequenceId;         // increments
    uint8_t controlOtherMessage; // 5
    uint8_t logMessagePeriod;    // 0
  };

  // this is the extra part for an Announce message
  struct __attribute__((__packed__)) ptp_announce {
    uint8_t originTimestamp[10];
    uint16_t currentUtcOffset;
    uint8_t reserved1;
    uint8_t grandmasterPriority1;
    uint32_t grandmasterClockQuality;
    uint8_t grandmasterPriority2;
    uint8_t grandmasterIdentity[8];
    uint16_t stepsRemoved;
    uint8_t timeSource;
  };

  // this is the extra part for a Sync or Delay_Req message
  struct __attribute__((__packed__)) ptp_sync {
    uint8_t originTimestamp[10];
  };

  // this is the extra part for a Sync or Delay_Req message
  struct __attribute__((__packed__)) ptp_delay_req {
    uint8_t originTimestamp[10];
  };

  // this is the extra part for a Follow_Up message
  struct __attribute__((__packed__)) ptp_follow_up {
    uint8_t preciseOriginTimestamp[10];
  };

  // this is the extra part for a Delay_Resp message
  struct __attribute__((__packed__)) ptp_delay_resp {
    uint8_t receiveTimestamp[10];
    uint8_t requestingPortIdentity[10];
  };

  struct __attribute__((__packed__)) ptp_sync_message {
    struct ptp_common_message_header header;
    struct ptp_sync sync;
  };

  struct __attribute__((__packed__)) ptp_delay_req_message {
    struct ptp_common_message_header header;
    struct ptp_delay_req delay_req;
  };

  struct __attribute__((__packed__)) ptp_follow_up_message {
    struct ptp_common_message_header header;
    struct ptp_follow_up follow_up;
  };

  struct __attribute__((__packed__)) ptp_delay_resp_message {
    struct ptp_common_message_header header;
    struct ptp_delay_resp delay_resp;
  };

  struct __attribute__((__packed__)) ptp_announce_message {
    struct ptp_common_message_header header;
    struct ptp_announce announce;
  };

#endif