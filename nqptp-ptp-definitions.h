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

#ifndef NQPTP_PTP_DEFINITIONS_H
#define NQPTP_PTP_DEFINITIONS_H

#include <inttypes.h>

// This is for definitions and stuff that flows more or less directly
// from external sources.

// They may not be used. Yet.

// Derived from
// https://github.com/rroussel/OpenAvnu/blob/ArtAndLogic-aPTP-changes/daemons/gptp/gptp_cfg.ini:

#define aPTPpriority1 248
#define aPTPpriority2 248
#define aPTPaccuracy 254

// "Per the Apple Vendor PTP profile"
// these seem to be log2 of seconds, thus 0 is 2^0 or 1 sec, -3 to 2^-3 or 0.125 sec
// see 7.7.7.2
#define aPTPinitialLogAnnounceInterval 0

// see 7.7.2.3
#define aPTPinitialLogSyncInterval -3

// This doesn't seem to be used in OpenAvnu
// but see 7.7.3.1, so it looks like they are units of the announceInterval, so seconds here
#define aPTPannounceReceiptTimeout 120

// "Per the Apple Vendor PTP profile (8*announceReceiptTimeout)"
// This doesn't seem to be used in OpenAvnu
// Guess it's the same idea, but based on aPTPinitialLogSyncInterval
// but it could be based on aPTPinitialLogAnnounceInterval, of course.

#define aPTPsyncReceiptTimeout 960

// "Neighbor propagation delay threshold in nanoseconds"
#define aPTPneighborPropDelayThresh 800

// "Sync Receipt Threshold
// This value defines the number of syncs with wrong seqID that will trigger
// the ptp slave to become master (it will start announcing)
// Normally sync messages are sent every 125ms, so setting it to 8 will allow
// up to 1 second of wrong messages before switching"

#define aPTPsyncReceiptThresh 8

// References from the IEEE Document ISBN 978-0-7381-5400-8 STD95773.
// "IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and
// Control Systems" The IEEE Std 1588-2008 (Revision of IEEE Std 1588-2002)

// See 9.3.2.4.4 FOREIGN_MASTER_TIME_WINDOW and FOREIGN_MASTER_THRESHOLD
// units are the announceInterval
#define FOREIGN_MASTER_TIME_WINDOW 4
#define FOREIGN_MASTER_THRESHOLD 2

// See also 9.3.2.5 Qualification of Announce messages

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

// Table 34, part of
enum tlvTypeValue {
  Reserved,
  // Standard TLVs
  MANAGEMENT,
  MANAGEMENT_ERROR_STATUS,
  ORGANIZATION_EXTENSION,
  // Optional unicast message negotiation TLVs
  REQUEST_UNICAST_TRANSMISSION,
  GRANT_UNICAST_TRANSMISSION,
  CANCEL_UNICAST_TRANSMISSION,
  ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION,
  // Optional path trace mechanism TLV
  PATH_TRACE,
  // Optional alternate timescale TLV
  ALTERNATE_TIME_OFFSET_INDICATOR
  // there are more, but not needed yet
};

// Table 23
enum controlFieldValue {
  Control_Field_Value_Sync,
  Control_Field_Value_Delay_Req,
  Control_Field_Value_Follow_Up,
  Control_Field_Value_Delay_Resp,
  Control_Field_Value_Management,
  Control_Field_Value_Other
};

// this is the structure of a PATH_TRACE TLV (16.2, Table 78, pp 164) without any space for the data
struct __attribute__((__packed__)) ptp_path_trace_tlv {
  uint16_t tlvType;
  uint16_t lengthField;
  uint8_t pathSequence[0];
};

// this is the structure of a TLV (14.3, Table 35, pp 135) without any space for the data
struct __attribute__((__packed__)) ptp_tlv {
  uint16_t tlvType;
  uint16_t lengthField;
  uint8_t organizationId[3];
  uint8_t organizationSubType[3];
  uint8_t dataField[0];
};

// this is the Common Message Header
struct __attribute__((__packed__)) ptp_common_message_header {
  uint8_t transportSpecificAndMessageID; // 0x11
  uint8_t reservedAndVersionPTP;         // 0x02
  uint16_t messageLength;
  uint8_t domainNumber;     // 0
  uint8_t reserved_b;       // 0
  uint16_t flags;           // 0x0608
  uint64_t correctionField; // 0
  uint32_t reserved_l;      // 0
  uint8_t clockIdentity[8]; // MAC
  uint16_t sourcePortID;    // 1
  uint16_t sequenceId;      // increments
  uint8_t controlField;     // 5
  uint8_t logMessagePeriod; // 0
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
  struct ptp_path_trace_tlv path_trace[0];
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
  // to be followed by zero or more TLVs
  struct ptp_tlv tlvs[0];
};

// this is the extra part for a Delay_Resp message
struct __attribute__((__packed__)) ptp_delay_resp {
  uint8_t receiveTimestamp[10];
  uint8_t requestingPortIdentity[10];
};

// this is the extra part for a Pdelay_Req message (13.9, pp 131)
struct __attribute__((__packed__)) ptp_pdelay_req {
  uint8_t originTimestamp[10];
  uint8_t reserved[10]; // to make it the same length as a Pdelay_Resp message
};

// this is the extra part for a Pdelay_Resp message (13.10, pp 131)
struct __attribute__((__packed__)) ptp_pdelay_resp {
  uint8_t requestReceiptTimestamp[10];
  uint8_t requestingPortIdentity[10];
};

// this is the extra part for a Signaling message (13.12, pp 132) without any TLVs
struct __attribute__((__packed__)) ptp_signaling {
  uint8_t targetPortIdentity[10];
  // to be followed by _one_ or more TLVs
  struct ptp_tlv tlvs[0];
};

struct __attribute__((__packed__)) ptp_pdelay_req_message {
  struct ptp_common_message_header header;
  struct ptp_pdelay_req pdelay_req;
};

struct __attribute__((__packed__)) ptp_pdelay_resp_message {
  struct ptp_common_message_header header;
  struct ptp_pdelay_resp pdelay_resp;
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

struct __attribute__((__packed__)) ptp_signaling_message {
  struct ptp_common_message_header header;
  struct ptp_signaling signaling;
};

#endif