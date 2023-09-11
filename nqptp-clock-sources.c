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

#include "nqptp-clock-sources.h"
#include "debug.h"
#include "general-utilities.h"
#include "nqptp-ptp-definitions.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h> // for ftruncate and others
#include <unistd.h>    // for ftruncate and others

#include <fcntl.h>      /* For O_* constants */
#include <sys/mman.h>   // for shared memory stuff
#include <sys/select.h> // for fd_set
#include <sys/stat.h>   // umask

#ifdef CONFIG_FOR_FREEBSD
#include <netinet/in.h>
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

int shm_fd;
struct shm_structure *shared_memory;

clock_source_private_data clocks_private[MAX_CLOCKS];
client_record clients[MAX_CLIENTS];

/*
const char *get_client_name(int client_id) {
  if ((client_id >= 0) && (client_id < MAX_CLIENTS)) {
    return clients[client_id].shm_interface_name;
  } else {
    return "";
  }
}
*/

int get_client_id(char *client_shared_memory_interface_name) {
  int response = -1; // signify not found
  if (client_shared_memory_interface_name != NULL) {
    int i = 0;
    // first, see if yu can find it anywhere
    while ((response == -1) && (i < MAX_CLIENTS)) {
      if (strcmp(clients[i].shm_interface_name, client_shared_memory_interface_name) == 0)
        response = i;
      else
        i++;
    }

    if (response == -1) { // no match, so create one
      i = 0;
      while ((response == -1) && (i < MAX_CLIENTS)) {
        if (clients[i].shm_interface_name[0] == '\0')
          response = i;
        else
          i++;
      }
      if (response != -1) {
        strncpy(clients[i].shm_interface_name, client_shared_memory_interface_name,
                sizeof(clients[i].shm_interface_name));
        // create the named smi interface

        // open a shared memory interface.
        debug(2, "Create a shm interface named \"%s\"", clients[i].shm_interface_name);
        clients[i].shm_fd = -1;

        mode_t oldumask = umask(0);
        clients[i].shm_fd = shm_open(client_shared_memory_interface_name, O_RDWR | O_CREAT, 0666);
        if (clients[i].shm_fd == -1) {
          die("cannot open shared memory \"%s\".", client_shared_memory_interface_name);
        }
        (void)umask(oldumask);

        if (ftruncate(clients[i].shm_fd, sizeof(struct shm_structure)) == -1) {
          die("failed to set size of shared memory \"%s\".", client_shared_memory_interface_name);
        }

#ifdef CONFIG_FOR_FREEBSD
        clients[i].shared_memory =
            (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                         MAP_SHARED, clients[i].shm_fd, 0);
#endif

#ifdef CONFIG_FOR_LINUX
        clients[i].shared_memory =
            (struct shm_structure *)mmap(NULL, sizeof(struct shm_structure), PROT_READ | PROT_WRITE,
                                         MAP_LOCKED | MAP_SHARED, clients[i].shm_fd, 0);
#endif

        if (clients[i].shared_memory == (struct shm_structure *)-1) {
          die("failed to mmap shared memory \"%s\".", client_shared_memory_interface_name);
        }

        if ((close(clients[i].shm_fd) == -1)) {
          warn("error closing \"%s\" after mapping.", client_shared_memory_interface_name);
        }

        // zero it
        memset(clients[i].shared_memory, 0, sizeof(struct shm_structure));
        clients[i].shared_memory->version = NQPTP_SHM_STRUCTURES_VERSION;

        // for (i = 0; i < MAX_CLOCKS; i++) {
        //  clocks_private[i].client_flags[response] =
        //      0; // turn off all client flags in every clock for this client
        // }
      } else {
        debug(1, "could not create a client record for client \"%s\".",
              client_shared_memory_interface_name);
      }
    }
  } else {
    debug(1, "no client_shared_memory_interface_name");
  }
  debug(2, "get_client_id \"%s\" response %d", client_shared_memory_interface_name, response);
  return response;
}

int delete_client(int client_id) {
  int response = 0; // okay unless something happens
  if (clients[client_id].shm_interface_name[0] != '\0') {
    if (clients[client_id].shared_memory != NULL) {
      // mmap cleanup
      if (munmap(clients[client_id].shared_memory, sizeof(struct shm_structure)) != 0) {
        debug(1, "error unmapping shared memory");
        response = -1;
      }
      // shm_open cleanup
      if (shm_unlink(clients[client_id].shm_interface_name) == -1) {
        debug(1, "error unlinking shared memory \"%s\"", clients[client_id].shm_interface_name);
        response = -1;
      }
    }
    clients[client_id].shm_interface_name[0] = '\0'; // remove the name to signify it's vacant
  }
  return response;
}

int delete_clients() {
  int response = 0; // okay unless something happens
  int i;
  for (i = 0; i < MAX_CLIENTS; i++)
    if (delete_client(i) != 0)
      response = -1;
  return response;
}

int find_clock_source_record(char *sender_string, clock_source_private_data *clocks_private_info) {
  // return the index of the clock in the clock information arrays or -1
  int response = -1;
  int i = 0;
  int found = 0;
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if (((clocks_private_info[i].flags & (1 << clock_is_in_use)) != 0) &&
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
  // return the index of a clock entry in the clock information arrays or -1 if full
  // initialise the entries in the shared and private arrays
  int response = -1;
  int i = 0;
  int found = 0; // trying to find an unused entry
  while ((found == 0) && (i < MAX_CLOCKS)) {
    if ((clocks_private_info[i].flags & (1 << clock_is_in_use)) == 0)
      found = 1;
    else
      i++;
  }

  if (found == 1) {
    int family = 0;

    // check its ipv4/6 family -- derived from https://stackoverflow.com/a/3736377, with thanks.
    struct addrinfo hint, *res = NULL;
    memset(&hint, '\0', sizeof hint);
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(sender_string, NULL, &hint, &res) == 0) {
      family = res->ai_family;
      freeaddrinfo(res);
      response = i;
      memset(&clocks_private_info[i], 0, sizeof(clock_source_private_data));
      strncpy((char *)&clocks_private_info[i].ip, sender_string,
              FIELD_SIZEOF(clock_source_private_data, ip) - 1);
      clocks_private_info[i].family = family;
      clocks_private_info[i].flags |= (1 << clock_is_in_use);
      debug(2, "create record for ip: %s, family: %s.", &clocks_private_info[i].ip,
            clocks_private_info[i].family == AF_INET6 ? "IPv6" : "IPv4");
    } else {
      debug(1, "cannot getaddrinfo for ip: %s.", &clocks_private_info[i].ip);
    }
  } else {
    debug(1, "Clock tables full!");
  }
  return response;
}

void update_master_clock_info(uint64_t master_clock_id, const char *ip, uint64_t local_time,
                              uint64_t local_to_master_offset, uint64_t mastership_start_time) {
  // to ensure that a full update has taken place, the
  // reader must ensure that the main and secondary
  // structures are identical

  shared_memory->main.master_clock_id = master_clock_id;
  if (ip != NULL) {
    shared_memory->main.master_clock_start_time = mastership_start_time;
    shared_memory->main.local_time = local_time;
    shared_memory->main.local_to_master_time_offset = local_to_master_offset;
  } else {
    shared_memory->main.master_clock_start_time = 0;
    shared_memory->main.local_time = 0;
    shared_memory->main.local_to_master_time_offset = 0;
  }
  __sync_synchronize();
  shared_memory->secondary = shared_memory->main;
  __sync_synchronize();
}
