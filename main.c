/*
 * This file is part of the nqPTP distribution (https://github.com/mikebrady/nqPTP).
 * Copyright (c) 2021 Mike Brady.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
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
#include <stdio.h>  //printf
#include <stdlib.h> //exit(0);
#include <string.h> //memset
#include <sys/socket.h>
#include <unistd.h> // close

#include <ifaddrs.h>
#include <sys/types.h>

#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <inttypes.h>

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

#define BUFLEN 4096 // Max length of buffer
#define PORT 320    // The port on which to listen for incoming data

struct sockaddr_in si_me_319, si_me_320, si_other;

uint64_t time_then = 0;

void die(char *s) {
  perror(s);
  exit(1);
}

uint32_t nctohl(const uint8_t *p) { // read 4 characters from *p and do ntohl on them
  // this is to avoid possible aliasing violations
  uint32_t holder;
  memcpy(&holder, p, sizeof(holder));
  return ntohl(holder);
}

uint16_t nctohs(const uint8_t *p) { // read 2 characters from *p and do ntohs on them
  // this is to avoid possible aliasing violations
  uint16_t holder;
  memcpy(&holder, p, sizeof(holder));
  return ntohs(holder);
}

uint64_t timespec_to_ns(struct timespec *tn) {
  uint64_t tnfpsec = tn->tv_sec;
  uint64_t tnfpnsec = tn->tv_nsec;
  tnfpsec = tnfpsec * 1000000000;
  return tnfpsec + tnfpnsec;
}

uint64_t get_time_now() {
  struct timespec tn;
  clock_gettime(CLOCK_MONOTONIC, &tn); // this should be optionally CLOCK_MONOTONIC etc.
  return timespec_to_ns(&tn);
}

void print_buffer(char *buf, size_t buf_len) {
  uint64_t time_now = get_time_now();
  if (time_then == 0) {
    printf("          ");
  } else {
    printf("%f  ", (time_now - time_then) * 0.000000001);
  }
  time_then = time_now;
  // printf("Received %u bytes in a packet from %s:%d\n", buf_len, inet_ntoa(si_other.sin_addr),
  // ntohs(si_other.sin_port));
  char obf[BUFLEN * 2 + BUFLEN / 4 + 1 + 1];
  char *obfp = obf;
  unsigned int obfc;
  for (obfc = 0; obfc < buf_len; obfc++) {
    snprintf(obfp, 3, "%02X", buf[obfc]);
    obfp += 2;
    if (obfc != buf_len - 1) {
      if (obfc % 32 == 31) {
        snprintf(obfp, 5, " || ");
        obfp += 4;
      } else if (obfc % 16 == 15) {
        snprintf(obfp, 4, " | ");
        obfp += 3;
      } else if (obfc % 4 == 3) {
        snprintf(obfp, 2, " ");
        obfp += 1;
      }
    }
  };
  *obfp = 0;
  switch (buf[0]) {

  case 0x10:
    printf("SYNC: \"%s\".\n", obf);
    break;
  case 0x18:
    printf("FLUP: \"%s\".\n", obf);
    break;
  case 0x19:
    printf("DRSP: \"%s\".\n", obf);
    break;
  case 0x1B:
    printf("ANNC: \"%s\".\n", obf);
    break;
  case 0x1C:
    printf("SGNL: \"%s\".\n", obf);
    break;
  default:
    printf("      \"%s\".\n", obf);
    break;
  }
}

int main(void) {
  int s319, s320;
  unsigned int slen = sizeof(si_other);
  ssize_t recv_len;

  char buf[BUFLEN];

  int status;

  uint64_t previous_offset = 0;

  struct __attribute__((__packed__)) ptp_common_message_header {
    uint8_t transportSpecificAndMessageID; // 0x11
    uint8_t reservedAndVersionPTP;         // 0x02
    uint16_t messageLength;
    uint8_t domainNumber;        // 0
    uint8_t reserved_b;          // 0
    uint16_t flags;              // 0x0608
    uint8_t correctionNs[6];     // 0
    uint8_t correctionSubNs[2];  // 0
    uint32_t reserved_l;         // 0
    uint8_t clockIdentity[8];    // MAC
    uint16_t sourcePortID;       // 1
    uint16_t sequenceId;         // increments
    uint8_t controlOtherMessage; // 5
    uint8_t logMessagePeriod;    // 0
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
  } ;

  struct __attribute__((__packed__)) ptp_follow_up_message {
    struct ptp_common_message_header header;
    struct ptp_follow_up follow_up;
  } ;

  struct __attribute__((__packed__)) ptp_delay_resp_message {
    struct ptp_common_message_header header;
    struct ptp_delay_resp delay_resp;
  };

  struct ptp_delay_req_message m;

  // create a UDP socket
  if ((s319 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    die("socket319");
  }

  // zero out the structure
  memset((char *)&si_me_319, 0, sizeof(si_me_319));

  si_me_319.sin_family = AF_INET;
  si_me_319.sin_port = htons(319);
  si_me_319.sin_addr.s_addr = htonl(INADDR_ANY);

  // bind socket to port
  if (bind(s319, (struct sockaddr *)&si_me_319, sizeof(si_me_319)) == -1) {
    die("bind 319");
  }

  // create a UDP socket
  if ((s320 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    die("socket320");
  }

  // zero out the structure
  memset((char *)&si_me_320, 0, sizeof(si_me_320));

  si_me_320.sin_family = AF_INET;
  si_me_320.sin_port = htons(320);
  si_me_320.sin_addr.s_addr = htonl(INADDR_ANY);

  // bind socket to port
  if (bind(s320, (struct sockaddr *)&si_me_320, sizeof(si_me_320)) == -1) {
    die("bind 320");
  }

  fd_set readSockSet;
  struct timeval timeout;
  int smax = s319;
  if (smax < s320)
    smax = s320;

  while (1) {
    FD_ZERO(&readSockSet);
    FD_SET(s319, &readSockSet);
    FD_SET(s320, &readSockSet);
    // add connected TCP clients, if needed...

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    int retval = select(smax + 1, &readSockSet, NULL, NULL, &timeout);
    uint64_t t1, t2, t3, t4, t5;
    uint64_t reception_time = get_time_now();

    if (retval > 0) {
      // note time of arrival
      if (FD_ISSET(s319, &readSockSet)) {
        // printf("S319 Client query incoming...\n");
        // try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(s319, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen)) ==
            -1) {
          die("recvfrom() 319");
        } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
          // print_buffer(buf, recv_len);
          switch (buf[0] & 0xF) {
          case Sync: { // if it's a sync
            struct ptp_sync_message *msg = (struct ptp_sync_message *)buf;
            t2 = reception_time;
            memset(&m, 0, sizeof(m));
            m.header.transportSpecificAndMessageID = 0x11;
            m.header.reservedAndVersionPTP = 0x02;
            m.header.messageLength = htons(44);
            m.header.flags = htons(0x608);
            m.header.sourcePortID = htons(1);
            m.header.controlOtherMessage = 5;
            m.header.sequenceId = msg->header.sequenceId;
            struct ifaddrs *ifaddr = NULL;
            struct ifaddrs *ifa = NULL;

            if ((status = getifaddrs(&ifaddr) == -1)) {
              fprintf(stderr, "getifaddrs: %s\n", gai_strerror(status));
            } else {
              int found = 0;
              for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
                  struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                  if ((strcmp(ifa->ifa_name, "lo") != 0) && (found == 0)) {
                    memcpy(&m.header.clockIdentity, &s->sll_addr, s->sll_halen);
                    found = 1;
                  }
                }
              }
              freeifaddrs(ifaddr);
            }
            t3 = get_time_now();
            if (sendto(s319, &m, sizeof(m), 0, (const struct sockaddr *)&si_other, slen) == -1) {
              fprintf(stderr, "sendto: %s\n", strerror(errno));
              return 4;
            }
          } break;
          default:
            break;
          }
        }
      }

      if (FD_ISSET(s320, &readSockSet)) {
        // printf("S320 Client query incoming...\n");
        // try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(s320, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen)) ==
            -1) {
          die("recvfrom() 320");

        } else if (recv_len >= (ssize_t)sizeof(struct ptp_common_message_header)) {
          //print_buffer(buf, recv_len);
          switch (buf[0] & 0xF) {
          case Follow_Up: {
            struct ptp_follow_up_message *msg = (struct ptp_follow_up_message *)buf;
            uint16_t seconds_hi = nctohs(&msg->follow_up.preciseOriginTimestamp[0]);
            uint32_t seconds_low = nctohl(&msg->follow_up.preciseOriginTimestamp[2]);
            uint32_t nanoseconds = nctohl(&msg->follow_up.preciseOriginTimestamp[6]);
            uint64_t preciseOriginTimestamp = seconds_hi;
            preciseOriginTimestamp = preciseOriginTimestamp << 32;
            preciseOriginTimestamp = preciseOriginTimestamp + seconds_low;
            preciseOriginTimestamp = preciseOriginTimestamp * 1000000000L;
            preciseOriginTimestamp = preciseOriginTimestamp + nanoseconds;
            t1 = preciseOriginTimestamp;
          } break;
          case Delay_Resp: {
          	struct ptp_delay_resp_message *msg = (struct ptp_delay_resp_message *)buf;
            uint16_t seconds_hi = nctohs(&msg->delay_resp.receiveTimestamp[0]);
            uint32_t seconds_low = nctohl(&msg->delay_resp.receiveTimestamp[2]);
            uint32_t nanoseconds = nctohl(&msg->delay_resp.receiveTimestamp[6]);
            uint64_t receiveTimestamp = seconds_hi;
            receiveTimestamp = receiveTimestamp << 32;
            receiveTimestamp = receiveTimestamp + seconds_low;
            receiveTimestamp = receiveTimestamp * 1000000000L;
            receiveTimestamp = receiveTimestamp + nanoseconds;
            t4 = receiveTimestamp;
            t5 = reception_time; // t5 - t3 gives us the out-and-back time locally -- an instantaneous quality index

            // calculate delay and calculate offset
            //fprintf(stderr, "t1: %016" PRIx64 ", t2: %" PRIx64 ", t3: %" PRIx64 ", t4: %" PRIx64 ".\n",t1,t2,t3,t4);
            //fprintf(stderr, "nominal remote transaction time: %" PRIx64 " = %" PRIu64 "ns; local transaction time: %" PRIx64 " = %" PRId64 "ns.\n", t4-t1, t4-t1, t3-t2, t3-t2);
            uint64_t offset = t1 - t2;
            if (previous_offset == 0)
            	fprintf(stderr, "offset: %" PRIx64 ".\n", offset);
            else {
            	int64_t variation = offset - previous_offset;
            	fprintf(stderr, "remote transaction time: %f, offset: %" PRIx64 ", variation: %f, turnaround: %f \n", (t4-t1) * 0.000000001, offset, variation * 0.000000001, (t5 - t2) * 0.000000001);
            }
						previous_offset = offset;
            //fprintf(stderr, "Offset: %" PRIx64 ", delay %f.\n", offset, delay*0.000000001);

          } break;

          default:
            // fprintf(stderr, "320 other\n");
            break;
          }
        }
      }

    } else if (retval < 0) {
      // check errno/WSAGetLastError(), call perror(), etc ...
    }
  }
  close(s319);
  close(s320);
  return 0;
}