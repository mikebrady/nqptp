#ifndef NQPTP_PLATFORM_H
#define NQPTP_PLATFORM_H

#include "nqptp-shm-structures.h"
#include <inttypes.h>
#include <stddef.h>

#ifdef CONFIG_FOR_MINGW
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET nqptp_socket_t;
typedef ADDRESS_FAMILY sa_family_t;
#define NQPTP_INVALID_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
typedef int nqptp_socket_t;
#define NQPTP_INVALID_SOCKET (-1)
#endif

int nqptp_platform_init(void);
void nqptp_platform_cleanup(void);
int nqptp_socket_close(nqptp_socket_t *fd);
int nqptp_socket_set_nonblocking(nqptp_socket_t fd);
int nqptp_socket_error(void);
int nqptp_socket_would_block(int error);

struct shm_structure *nqptp_shared_memory_create(const char *name, size_t size, int locked);
int nqptp_shared_memory_unmap(struct shm_structure *addr, size_t size);
int nqptp_shared_memory_unlink(const char *name);

int nqptp_get_device_id(uint8_t *id, int *int_length);

#endif
