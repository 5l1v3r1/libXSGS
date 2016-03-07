#######################################
# The list of executables we are building seperated by spaces
# the 'bin_' indicates that these build products will be installed
# in the $(bindir) directory. For example /usr/bin
#bin_PROGRAMS=demo

# Because a.out is only a sample program we don't want it to be installed.
# The 'noinst_' prefix indicates that the following targets are not to be
# installed.
noinst_PROGRAMS = dummy client server user grpmgr

#######################################
# Build information for each executable. The variable name is derived
# by use the name of the executable with each non alpha-numeric character is
# replaced by '_'. So a.out becomes a_out and the appropriate suffex added.
# '_SOURCES' for example.

# Sources for the a.out 
dummy_SOURCES = dummy.c demo.c
client_SOURCES = client.c demo.c
server_SOURCES = server.c demo.c
user_SOURCES = user.c demo.c
grpmgr_SOURCES = grpmgr.c demo.c

# Linker options for a.out
dummy_LDFLAGS = -lssl
client_LDFLAGS = $(top_srcdir)/libxsgs/libxsgs.la -lpthread -lssl
server_LDFLAGS = $(top_srcdir)/libxsgs/libxsgs.la -lpthread -lssl
user_LDFLAGS = $(top_srcdir)/libxsgs/libxsgs.la -lssl
grpmgr_LDFLAGS = $(top_srcdir)/libxsgs/libxsgs.la -lpthread -lssl

# Compiler options for a.out
dummy_CPPFLAGS = 
client_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc
server_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc
user_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc
grpmgr_CPPFLAGS = -I$(top_srcdir)/include -I$(includedir)/pbc