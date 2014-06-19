dnl Process this file with autoconf
AC_INIT(bruteforce_salted_openssl, 1.0)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(src/bruteforce-salted-openssl.c)

dnl Check for toolchain and install components
AC_PROG_CC
AC_PROG_INSTALL

dnl Check for standard headers
AC_CHECK_HEADERS([ctype.h fcntl.h stdio.h stdlib.h string.h sys/stat.h sys/types.h unistd.h])

dnl Check for functions
AC_CHECK_FUNCS([malloc free])
AC_CHECK_FUNCS([perror printf fprintf])
AC_CHECK_FUNCS([atoi isprint])
AC_CHECK_FUNCS([memset strcasecmp strlen strncmp])
AC_CHECK_FUNCS([open fstat read close])
AC_CHECK_FUNCS([getopt])

dnl Check for libraries
AC_CHECK_LIB(pthread, pthread_create, [], AC_MSG_ERROR([POSIX threads library required]))
AC_CHECK_HEADERS(pthread.h, [], AC_MSG_ERROR([OpenSSL headers required]))

AC_CHECK_LIB(crypto, EVP_get_cipherbyname, [],AC_MSG_ERROR([OpenSSL libraries required]))
AC_CHECK_HEADERS(openssl/evp.h, [], AC_MSG_ERROR([OpenSSL headers required]))

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
