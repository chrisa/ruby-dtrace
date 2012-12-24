require 'mkmf'
require 'rbconfig'

# Need to specify full path to dtrace.h or we'll pick up ruby's
# dtrace.h on Solaris or other builds with the runtime probes included.
have_library("dtrace", "dtrace_open", "/usr/include/dtrace.h")
create_makefile("dtrace_api")
