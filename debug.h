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

// four level debug message utility giving file and line, total elapsed time, interval time
// warn / inform / debug / die calls.

// level 0 is no messages, level 3 is most messages
void debug_init(int level, int show_elapsed_time, int show_relative_time, int show_file_and_line);

void _die(const char *filename, const int linenumber, const char *format, ...);
void _warn(const char *filename, const int linenumber, const char *format, ...);
void _inform(const char *filename, const int linenumber, const char *format, ...);
void _debug(const char *filename, const int linenumber, int level, const char *format, ...);

#define die(...) _die(__FILE__, __LINE__, __VA_ARGS__)
#define debug(...) _debug(__FILE__, __LINE__, __VA_ARGS__)
#define warn(...) _warn(__FILE__, __LINE__, __VA_ARGS__)
#define inform(...) _inform(__FILE__, __LINE__, __VA_ARGS__)
