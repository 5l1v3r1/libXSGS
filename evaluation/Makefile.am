#######################################
# The list of executables we are building seperated by spaces
# the 'bin_' indicates that these build products will be installed
# in the $(bindir) directory. For example /usr/bin
#bin_PROGRAMS=evaluation

# Because a.out is only a sample program we don't want it to be installed.
# The 'noinst_' prefix indicates that the following targets are not to be
# installed.
noinst_PROGRAMS=evaluation

#######################################
# Build information for each executable. The variable name is derived
# by use the name of the executable with each non alpha-numeric character is
# replaced by '_'. So a.out becomes a_out and the appropriate suffex added.
# '_SOURCES' for example.

# Sources for the a.out 
evaluation_SOURCES= evaluation.c xsgs_bench.c xsgs_eval.c

# Linker options for a.out
evaluation_LDFLAGS = $(top_srcdir)/libxsgs/libxsgs.la

# Compiler options for a.out
evaluation_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc
