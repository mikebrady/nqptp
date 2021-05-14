#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([nqptp], [1.1-dev], [4265913+mikebrady@users.noreply.github.com])
AM_INIT_AUTOMAKE

AC_CHECK_PROGS([GIT], [git])
if test -n "$GIT"; then
  AC_DEFINE([CONFIG_USE_GIT_VERSION_STRING], 1, [Use the version string produced by running 'git describe --dirty'.])
fi
AM_CONDITIONAL([USE_GIT], [test -n "$GIT"])

AC_CONFIG_SRCDIR([nqptp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pthread],[pthread_create], , AC_MSG_ERROR(pthread library needed))
AC_CHECK_LIB([rt],[clock_gettime], , AC_MSG_ERROR(librt needed for shared memory library))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netdb.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime inet_ntoa memset select socket strerror])

AC_CONFIG_FILES([Makefile nqptp.service])
AC_OUTPUT
