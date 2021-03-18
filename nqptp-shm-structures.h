#ifndef NQPTP_SHM_STRUCTURES_H
#define NQPTP_SHM_STRUCTURES_H

#define MAX_SHARED_CLOCKS 8
#define NQPTP_SHM_STRUCTURES_VERSION 1

#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>

struct __attribute__((__packed__)) clock_source {
    char ip[INET6_ADDRSTRLEN]; // where it's coming from
    int flags;                 // not used yet
    int valid;                 // this entry is valid
    uint64_t source_time;     // the time at the source at
    uint64_t local_time;       // the local time when the source time is valid
    uint64_t local_to_source_time_offset; // add this to the local time to get source time
};

struct __attribute__((__packed__)) shm_basic_structure {
};

struct __attribute__((__packed__)) shm_structure {
    pthread_mutex_t shm_mutex; // for safely accessing the structure
    uint16_t size_of_clock_array; // check this is equal to MAX_SHARED_CLOCKS
    uint16_t version; // check this is equal to NQPTP_SHM_STRUCTURES_VERSION
    uint32_t flags;
    struct clock_source clocks[MAX_SHARED_CLOCKS];
};

#endif
