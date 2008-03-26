require 'mkmf'
$CFLAGS += " -D_LONGLONG_TYPE -g"
have_header("sys/dtrace.h")
create_makefile("parser")
