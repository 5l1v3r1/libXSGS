#######################################
# The list of libraries we are building seperated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = libxsgs.la

#######################################
# Build information for each library

# Sources for libxsgs
libxsgs_la_SOURCES = xsgs_clear.c \
					 xsgs_gen.c \
					 xsgs_io.c \
					 xsgs_join.c \
					 xsgs_open.c \
					 xsgs_revoke.c \
					 xsgs_sig.c \
					 xsgs_paillier.c \
					 xsgs_hash.c \
					 xsgs_rsa.c \
					 xsgs_util.c \
					 xsgs_arith.c \
					 ../sha3/KeccakNISTInterface.c \
					 ../sha3/KeccakSponge.c

if ARCH_X86
libxsgs_la_SOURCES += ../sha3/KeccakF-1600-opt32.c
else
if ARCH_X64
libxsgs_la_SOURCES += ../sha3/KeccakF-1600-opt64.c
else
if ARCH_ARM
libxsgs_la_SOURCES += ../sha3/KeccakF-1600-arm.c ../sha3/KeccakF-1600-armgcc.s
else # should be a generic implementation
libxsgs_la_SOURCES += ../sha3/KeccakF-1600-opt32.c
endif
endif
endif

# Linker options libTestProgram
libxsgs_la_LDFLAGS = -lm

# Compiler options. Here we are adding the include directory
# to be searched for headers included in the source code.
libxsgs_la_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc -I$(top_srcdir)/sha3

