require 'mkmf'
$CFLAGS += " -D_LONGLONG_TYPE"
have_library("dtrace", "dtrace_open")
create_makefile("dtrace_api")
