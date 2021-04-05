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

#include "debug.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

int debuglev = 0;
int debugger_show_elapsed_time = 0;
int debugger_show_relative_time = 0;
int debugger_show_file_and_line = 1;

uint64_t ns_time_at_startup = 0;
uint64_t ns_time_at_last_debug_message;

// always lock use this when accessing the ns_time_at_last_debug_message
static pthread_mutex_t debug_timing_lock = PTHREAD_MUTEX_INITIALIZER;

uint64_t get_absolute_time_in_ns() {
  uint64_t time_now_ns;
  struct timespec tn;
  // CLOCK_REALTIME because PTP uses it.
  clock_gettime(CLOCK_REALTIME, &tn);
  uint64_t tnnsec = tn.tv_sec;
  tnnsec = tnnsec * 1000000000;
  uint64_t tnjnsec = tn.tv_nsec;
  time_now_ns = tnnsec + tnjnsec;
  return time_now_ns;
}

void debug_init(int level, int show_elapsed_time, int show_relative_time, int show_file_and_line) {
  ns_time_at_startup = get_absolute_time_in_ns();
  ns_time_at_last_debug_message = ns_time_at_startup;
  debuglev = level;
  debugger_show_elapsed_time = show_elapsed_time;
  debugger_show_relative_time = show_relative_time;
  debugger_show_file_and_line = show_file_and_line;
}

char *generate_preliminary_string(char *buffer, size_t buffer_length, double tss, double tsl,
                                  const char *filename, const int linenumber, const char *prefix) {
  size_t space_remaining = buffer_length;
  char *insertion_point = buffer;
  if (debugger_show_elapsed_time) {
    snprintf(insertion_point, space_remaining, "% 20.9f", tss);
    insertion_point = insertion_point + strlen(insertion_point);
    space_remaining = space_remaining - strlen(insertion_point);
  }
  if (debugger_show_relative_time) {
    snprintf(insertion_point, space_remaining, "% 20.9f", tsl);
    insertion_point = insertion_point + strlen(insertion_point);
    space_remaining = space_remaining - strlen(insertion_point);
  }
  if (debugger_show_file_and_line) {
    snprintf(insertion_point, space_remaining, " \"%s:%d\"", filename, linenumber);
    insertion_point = insertion_point + strlen(insertion_point);
    space_remaining = space_remaining - strlen(insertion_point);
  }
  if (prefix) {
    snprintf(insertion_point, space_remaining, "%s", prefix);
    insertion_point = insertion_point + strlen(insertion_point);
    space_remaining = space_remaining - strlen(insertion_point);
  }
  return insertion_point;
}

void _die(const char *filename, const int linenumber, const char *format, ...) {
  int oldState;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldState);
  char b[1024];
  b[0] = 0;
  char *s;
  if (debuglev) {
    pthread_mutex_lock(&debug_timing_lock);
    uint64_t time_now = get_absolute_time_in_ns();
    uint64_t time_since_start = time_now - ns_time_at_startup;
    uint64_t time_since_last_debug_message = time_now - ns_time_at_last_debug_message;
    ns_time_at_last_debug_message = time_now;
    pthread_mutex_unlock(&debug_timing_lock);
    s = generate_preliminary_string(b, sizeof(b), 1.0 * time_since_start / 1000000000,
                                    1.0 * time_since_last_debug_message / 1000000000, filename,
                                    linenumber, " *fatal error: ");
  } else {
    strncpy(b, "fatal error: ", sizeof(b));
    s = b + strlen(b);
  }
  va_list args;
  va_start(args, format);
  vsnprintf(s, sizeof(b) - (s - b), format, args);
  va_end(args);
  // syslog(LOG_ERR, "%s", b);
  fprintf(stderr, "%s\n", b);
  pthread_setcancelstate(oldState, NULL);
  exit(EXIT_FAILURE);
}

void _warn(const char *filename, const int linenumber, const char *format, ...) {
  int oldState;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldState);
  char b[1024];
  b[0] = 0;
  char *s;
  if (debuglev) {
    pthread_mutex_lock(&debug_timing_lock);
    uint64_t time_now = get_absolute_time_in_ns();
    uint64_t time_since_start = time_now - ns_time_at_startup;
    uint64_t time_since_last_debug_message = time_now - ns_time_at_last_debug_message;
    ns_time_at_last_debug_message = time_now;
    pthread_mutex_unlock(&debug_timing_lock);
    s = generate_preliminary_string(b, sizeof(b), 1.0 * time_since_start / 1000000000,
                                    1.0 * time_since_last_debug_message / 1000000000, filename,
                                    linenumber, " *warning: ");
  } else {
    strncpy(b, "warning: ", sizeof(b));
    s = b + strlen(b);
  }
  va_list args;
  va_start(args, format);
  vsnprintf(s, sizeof(b) - (s - b), format, args);
  va_end(args);
  // syslog(LOG_WARNING, "%s", b);
  fprintf(stderr, "%s\n", b);
  pthread_setcancelstate(oldState, NULL);
}

void _debug(const char *filename, const int linenumber, int level, const char *format, ...) {
  if (level > debuglev)
    return;
  int oldState;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldState);
  char b[1024];
  b[0] = 0;
  pthread_mutex_lock(&debug_timing_lock);
  uint64_t time_now = get_absolute_time_in_ns();
  uint64_t time_since_start = time_now - ns_time_at_startup;
  uint64_t time_since_last_debug_message = time_now - ns_time_at_last_debug_message;
  ns_time_at_last_debug_message = time_now;
  pthread_mutex_unlock(&debug_timing_lock);
  char *s = generate_preliminary_string(b, sizeof(b), 1.0 * time_since_start / 1000000000,
                                        1.0 * time_since_last_debug_message / 1000000000, filename,
                                        linenumber, " ");
  va_list args;
  va_start(args, format);
  vsnprintf(s, sizeof(b) - (s - b), format, args);
  va_end(args);
  // syslog(LOG_DEBUG, "%s", b);
  fprintf(stderr, "%s\n", b);
  pthread_setcancelstate(oldState, NULL);
}

void _inform(const char *filename, const int linenumber, const char *format, ...) {
  int oldState;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldState);
  char b[1024];
  b[0] = 0;
  char *s;
  if (debuglev) {
    pthread_mutex_lock(&debug_timing_lock);
    uint64_t time_now = get_absolute_time_in_ns();
    uint64_t time_since_start = time_now - ns_time_at_startup;
    uint64_t time_since_last_debug_message = time_now - ns_time_at_last_debug_message;
    ns_time_at_last_debug_message = time_now;
    pthread_mutex_unlock(&debug_timing_lock);
    s = generate_preliminary_string(b, sizeof(b), 1.0 * time_since_start / 1000000000,
                                    1.0 * time_since_last_debug_message / 1000000000, filename,
                                    linenumber, " ");
  } else {
    s = b;
  }
  va_list args;
  va_start(args, format);
  vsnprintf(s, sizeof(b) - (s - b), format, args);
  va_end(args);
  // syslog(LOG_INFO, "%s", b);
  fprintf(stderr, "%s\n", b);
  pthread_setcancelstate(oldState, NULL);
}
