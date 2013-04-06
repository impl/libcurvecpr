AC_PREREQ(2.67)
AC_INIT(libcurvecpr, 0.1.0, nfontes+libcurvecpr@cynigram.com, libcurvecpr)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_SRCDIR([include/server.h])
AC_CONFIG_HEADER([include/config.h])
AC_CONFIG_MACRO_DIR([m4])

# Library version.
CURVECPR_LIBRARY_VERSION=1:0:0
AC_SUBST(CURVECPR_LIBRARY_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AM_PROG_CC_C_O

# Checks for libraries.
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8])
AC_SEARCH_LIBS([clock_gettime], [rt posix4])
AC_CHECK_LIB([sodium], [crypto_onetimeauth_poly1305_ref], [], [AC_MSG_ERROR([missing libsodium])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h stdint.h string.h time.h], [], [AC_MSG_ERROR([missing required header file(s)])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_CHECK_TYPE([struct timespec], [], [AC_MSG_ERROR([missing struct timespec])], [[#include <time.h>]])

# Checks for functions.
AC_CHECK_FUNCS([clock_gettime], [], [AC_MSG_ERROR([missing clock_gettime])])

# Checks for compiler flags.
CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"
AX_APPEND_COMPILE_FLAGS([-fno-strict-aliasing -fno-strict-overflow], [], [-Wno-error])
AX_CHECK_LINK_FLAG([-fstack-protector], [AX_APPEND_COMPILE_FLAGS([-fstack-protector], [], [-Wno-error])], [], [], [-Wno-error])
AX_CHECK_LINK_FLAG([-fstack-protector-all], [AX_APPEND_COMPILE_FLAGS([-fstack-protector-all], [], [-Wno-error])], [], [], [-Wno-error])
AX_APPEND_COMPILE_FLAGS([ dnl
    -Wall -Wextra -Wcast-qual -Wcast-align -Winline -Wmissing-prototypes -Wmissing-declarations dnl
    -Wwrite-strings -Wredundant-decls -Wpointer-arith -Wchar-subscripts -Wshadow -Wstrict-prototypes dnl
    -Wvariable-decl -Winit-self -Wdiv-by-zero -Wsometimes-uninitialized -Wbad-function-cast -Wcomment dnl
    -Wfloat-equal -Wformat=2 -Wimplicit -Wnormalized=id -Woverride-init -Wparentheses -Wswitch-enum dnl
    -Wno-unused-parameter dnl
], [], [-Wno-error])
AX_APPEND_LINK_FLAGS([-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack], [], [-Wno-error])

# Done!
AC_CONFIG_FILES([Makefile libcurvecpr.pc])
AC_OUTPUT
