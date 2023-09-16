#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([nqptp], [1.2.4], [4265913+mikebrady@users.noreply.github.com])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

build_linux=no
build_freebsd=no

# Detect the target system
case "${host_os}" in
    linux*)
        build_linux=yes
        ;;
    freebsd*)
        build_freebsd=yes
        ;;    
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

# Pass the conditionals to automake
AM_CONDITIONAL([BUILD_FOR_LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([BUILD_FOR_FREEBSD], [test "$build_freebsd" = "yes"])

if test "x$build_linux" = "xyes" ; then
  AC_DEFINE([CONFIG_FOR_LINUX], 1, [Build for Linux.])
fi
if test "x$build_freebsd" = "xyes" ; then
  AC_DEFINE([CONFIG_FOR_FREEBSD], 1, [Build for FreeBSD.])
fi

AC_CHECK_PROGS([GIT], [git])
if test -n "$GIT" && test -e ".git/index" ; then
  AC_DEFINE([CONFIG_USE_GIT_VERSION_STRING], 1, [Use the version string produced by running 'git describe --dirty'.])
fi
AM_CONDITIONAL([USE_GIT_VERSION], [test -n "$GIT" && test -e ".git/index" ])


# Check to see if we should include the systemd stuff to define it as a service
AC_ARG_WITH([systemd-startup],[AS_HELP_STRING([--with-systemd-startup],[install a systemd startup script during a make install])])
AM_CONDITIONAL([INSTALL_SYSTEMD_STARTUP], [test "x$with_systemd_startup" = "xyes"])

# Check to see if we should include the systemd stuff to define it as a service
AC_ARG_WITH([freebsd-startup],[AS_HELP_STRING([--with-freebsd-startup],[install a FreeBSD startup script during a make install])])
AM_CONDITIONAL([INSTALL_FREEBSD_STARTUP], [test "x$with_freebsd_startup" = "xyes"])


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
