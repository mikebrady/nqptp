#include "config.h"
#include "nqptp-platform.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CONFIG_FOR_MINGW
#include <iphlpapi.h>
#include <windows.h>

static void windows_shm_name(const char *name, char *buffer, size_t buffer_size) {
  const char *source = name;
  if ((source != NULL) && (*source == '/'))
    source++;
  snprintf(buffer, buffer_size, "Local\\%s", source != NULL ? source : "nqptp");
}

int nqptp_platform_init(void) {
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2, 2), &wsa);
}

void nqptp_platform_cleanup(void) { WSACleanup(); }

int nqptp_socket_close(nqptp_socket_t *fd) {
  int response = 0;
  if ((fd != NULL) && (*fd != NQPTP_INVALID_SOCKET)) {
    response = closesocket(*fd);
    *fd = NQPTP_INVALID_SOCKET;
  }
  return response;
}

int nqptp_socket_set_nonblocking(nqptp_socket_t fd) {
  u_long mode = 1;
  return ioctlsocket(fd, FIONBIO, &mode);
}

int nqptp_socket_error(void) { return WSAGetLastError(); }

int nqptp_socket_would_block(int error) { return error == WSAEWOULDBLOCK; }

struct shm_structure *nqptp_shared_memory_create(const char *name, size_t size, int locked) {
  (void)locked;
  char mapped_name[MAX_PATH];
  windows_shm_name(name, mapped_name, sizeof(mapped_name));
  HANDLE mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)size,
                                      mapped_name);
  if (mapping == NULL)
    return (struct shm_structure *)-1;

  struct shm_structure *addr =
      (struct shm_structure *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
  if (addr == NULL) {
    CloseHandle(mapping);
    return (struct shm_structure *)-1;
  }
  return addr;
}

int nqptp_shared_memory_unmap(struct shm_structure *addr, size_t size) {
  (void)size;
  return UnmapViewOfFile(addr) == 0 ? -1 : 0;
}

int nqptp_shared_memory_unlink(const char *name) {
  (void)name;
  return 0;
}

int nqptp_get_device_id(uint8_t *id, int *int_length) {
  ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG family = AF_UNSPEC;
  ULONG buffer_size = 0;
  DWORD rc = GetAdaptersAddresses(family, flags, NULL, NULL, &buffer_size);
  if (rc != ERROR_BUFFER_OVERFLOW)
    return -1;

  IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES *)malloc(buffer_size);
  if (addresses == NULL)
    return -1;

  int response = -1;
  rc = GetAdaptersAddresses(family, flags, NULL, addresses, &buffer_size);
  if (rc == NO_ERROR) {
    IP_ADAPTER_ADDRESSES *adapter = addresses;
    while (adapter != NULL) {
      if ((adapter->OperStatus == IfOperStatusUp) && (adapter->PhysicalAddressLength > 0) &&
          (adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK)) {
        int max_length = *int_length;
        if ((max_length == 0) || ((int)adapter->PhysicalAddressLength < max_length)) {
          max_length = adapter->PhysicalAddressLength;
          *int_length = max_length;
        }
        memcpy(id, adapter->PhysicalAddress, max_length);
        response = 0;
        break;
      }
      adapter = adapter->Next;
    }
  }

  free(addresses);
  return response;
}

#else
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int nqptp_platform_init(void) { return 0; }

void nqptp_platform_cleanup(void) {}

int nqptp_socket_close(nqptp_socket_t *fd) {
  int response = 0;
  if ((fd != NULL) && (*fd != NQPTP_INVALID_SOCKET)) {
    response = close(*fd);
    *fd = NQPTP_INVALID_SOCKET;
  }
  return response;
}

int nqptp_socket_set_nonblocking(nqptp_socket_t fd) {
  int flags = fcntl(fd, F_GETFL);
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int nqptp_socket_error(void) { return errno; }

int nqptp_socket_would_block(int error) { return error == EAGAIN; }

struct shm_structure *nqptp_shared_memory_create(const char *name, size_t size, int locked) {
  int shm_fd = shm_open(name, O_RDWR | O_CREAT, 0666);
  if (shm_fd == -1)
    return (struct shm_structure *)-1;
  if (ftruncate(shm_fd, size) == -1) {
    close(shm_fd);
    return (struct shm_structure *)-1;
  }
  int flags = MAP_SHARED;
#ifdef CONFIG_FOR_LINUX
  if (locked)
    flags |= MAP_LOCKED;
#else
  (void)locked;
#endif
  struct shm_structure *addr =
      (struct shm_structure *)mmap(NULL, size, PROT_READ | PROT_WRITE, flags, shm_fd, 0);
  close(shm_fd);
  return addr;
}

int nqptp_shared_memory_unmap(struct shm_structure *addr, size_t size) {
  return munmap(addr, size);
}

int nqptp_shared_memory_unlink(const char *name) { return shm_unlink(name); }
#endif
