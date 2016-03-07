dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([xsgs],[7.5],[martin.goll@rub.de])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AS

AC_CANONICAL_HOST
case $host_cpu in
	i?86) AM_CONDITIONAL(ARCH_X86, true) AM_CONDITIONAL(ARCH_X64, false) AM_CONDITIONAL(ARCH_ARM, false) ;;
	x86_64) AM_CONDITIONAL(ARCH_X86, false) AM_CONDITIONAL(ARCH_X64, true) AM_CONDITIONAL(ARCH_ARM, false) ;;
	arm*) AM_CONDITIONAL(ARCH_X86, false) AM_CONDITIONAL(ARCH_X64, false) AM_CONDITIONAL(ARCH_ARM, true) ;;
	*) AM_CONDITIONAL(ARCH_X86, false) AM_CONDITIONAL(ARCH_X64, false) AM_CONDITIONAL(ARCH_ARM, false) ;;
esac

# Checks for headers
header_err_msg="add its path to CPPFLAGS\nsee ./configure --help"
AC_CHECK_HEADER([gmp.h], [], [
	      echo "************************"
	      echo "gmp header not found"
	      echo -e $header_err_msg
	      echo "************************"
	      exit -1
	    ])
AC_CHECK_HEADER([pbc/pbc.h], [], [
	      echo "************************"
	      echo "pbc header not found"
	      echo -e $header_err_msg
	      echo "************************"
	      exit -1
	    ])
AC_CHECK_HEADER([openssl/rsa.h], [], [
	      echo "************************"
	      echo "openssl header not found"
	      echo -e $header_err_msg
	      echo "************************"
	      exit -1
	    ])

# Checks for libraries.
lib_err_msg="add its path to LDFLAGS\nsee ./configure --help"
AC_CHECK_LIB( [gmp], [__gmpz_init], [],[
	      echo "************************"
	      echo "gmp library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [pbc], [pbc_info], [],[
	      echo "************************"
	      echo "pbc library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [crypto], [OPENSSL_init], [],[
	      echo "************************"
	      echo "openssl library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])

# Checks for header files.
# AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

with_enable_debug="no"
AC_ARG_ENABLE( debug,
              [AS_HELP_STRING([--enable-debug],
              [Add extra debugging information. Forbid compiling optimization.])],
              [with_enable_debug="yes"],
              [with_enable_debug="no"])

with_enable_optimized="no"
AC_ARG_ENABLE( optimized, 
	           [AS_HELP_STRING([--enable-optimized],[Enable optimized build])],
               [with_enable_optimized="yes"],
	           [with_enable_optimized="no"])

with_tcmalloc="no"
AC_ARG_ENABLE( tcmalloc, 
	           [AS_HELP_STRING([--enable-tcmalloc],[Enable tcmalloc linking])],
               [with_tcmalloc="yes"],
	           [with_tcmalloc="no"])
	           
CFLAGS="-Wall -Wextra -Wfloat-equal -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wredundant-decls \
-Wendif-labels -Wshadow -pipe -ffast-math -std=gnu99"

if test $with_enable_debug == "yes"; then
    CFLAGS="$CFLAGS -g3 -O0"
elif test $with_enable_optimized == "yes"; then
	CFLAGS="$CFLAGS -fomit-frame-pointer -O3"
else
   	CFLAGS="$CFLAGS -g -O2"
fi

if test $with_tcmalloc == "yes"; then
	LDFLAGS="-ltcmalloc"
fi

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyname memset socket strerror malloc])

AC_CANONICAL_TARGET

dnl Initialize automake
AM_INIT_AUTOMAKE

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O 

dnl Initialize Libtool
LT_INIT

dnl Check if Libtool is present
dnl Libtool is used for building share libraries 
LT_INIT

AC_CONFIG_FILES(Makefile
                libxsgs/Makefile
                include/Makefile
                test/Makefile
				evaluation/Makefile
				sample/Makefile
                demo/Makefile)
AC_OUTPUT

echo -ne "\n"
echo "global build variables"
echo "-----------------------------------------"
echo `date`
echo "host info:        $host"
if test $with_enable_debug == "yes"; then
echo "build type:       debug"
elif test $with_enable_optimized == "yes"; then
echo "build type:       optimized"
else
echo "build type:       default"
fi
echo "link tcmalloc:    $with_tcmalloc"
echo "LDFLAGS:          $LDFLAGS"
echo "CFLAGS:           $CFLAGS"
#echo "CPPFLAGS:         $CPPFLAGS"
echo "-----------------------------------------"
echo -ne "\n"
