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

#include <stdio.h>
#include <stdlib.h>
#include "nqptp-utilities.h"
#include "debug.h"

void debug_print_buffer(int level, char *buf, size_t buf_len) {
  // printf("Received %u bytes in a packet from %s:%d\n", buf_len, inet_ntoa(si_other.sin_addr),
  // ntohs(si_other.sin_port));
  char *obf = malloc(buf_len * 4 + 1); // to be on the safe side -- 4 characters on average for each byte
  if (obf != NULL) {
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
    debug(level, "SYNC: \"%s\".", obf);
    break;
  case 0x18:
    debug(level, "FLUP: \"%s\".", obf);
    break;
  case 0x19:
    debug(level, "DRSP: \"%s\".", obf);
    break;
  case 0x1B:
    debug(level, "ANNC: \"%s\".", obf);
    break;
  case 0x1C:
    debug(level, "SGNL: \"%s\".", obf);
    break;
  default:
    debug(level, "      \"%s\".", obf);
    break;
  }
  free(obf);
  }
}

