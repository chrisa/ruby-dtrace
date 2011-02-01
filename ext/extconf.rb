require 'mkmf'
require 'rbconfig'

$CFLAGS += " -D_LONGLONG_TYPE"

# Need to specify full path to dtrace.h or we'll pick up ruby's
# dtrace.h on Solaris or other builds with the runtime probes included.
have_library("dtrace", "dtrace_open", "/usr/include/dtrace.h")

# Figure out target platform
os  = Config::CONFIG['target_os']
os.gsub!  /[0-9.]+$/, ''

# Snow Leopard handling: detect Universal build and invoke dual build of dtrace_probe.c
cpu = `uname -p`.chomp
if cpu == "i386"
  ldflags = Config::CONFIG['LDFLAGS']
  if ldflags =~ /i386/ && ldflags =~ /x86_64/
    puts "Universal build detected"
    apple_universal = true
  end
end

arch = "#{cpu}-#{os}"

# Set up generated Makefile to build everything except dtrace_probe.c
$srcs = %w{ dtrace_aggdata.c
            dtrace_dropdata.c
            dtrace_process.c
            dtrace_recdesc.c
            dtrace_api.c
            dtrace_errdata.c
            dtrace_probedata.c
            dtrace_program.c
            dtrace_util.c
            dtrace_bufdata.c
            dtrace_hdl.c
            dtrace_probedesc.c
            dtrace_programinfo.c
           }

$objs = []
for f in $srcs
  obj = File.basename(f, ".*") << ".o"
  $objs.push(obj)
end

$objs.push "dtrace_probe.o"

# Create makefile in the usual way
create_makefile("dtrace_api")

# Then append rule(s) to create dtrace_probe.c
begin
  mfile = open("Makefile", "ab")
  mfile.puts
  
  if apple_universal
    # create i386 .o and x86_64.o
    mfile.print "dtrace_probe_i386-darwin.o:\n\t$(CC) $(INCFLAGS) -arch i386 -o dtrace_probe_i386-darwin.o -c i386-darwin/dtrace_probe.c\n\n"
    mfile.print "dtrace_probe_x86_64-darwin.o:\n\t$(CC) $(INCFLAGS) -arch x86_64 -o dtrace_probe_x86_64-darwin.o  -c x86_64-darwin/dtrace_probe.c\n\n"

    # link those into a universal dtrace_probe.o
    mfile.print "dtrace_probe.o: dtrace_probe_i386-darwin.o dtrace_probe_x86_64-darwin.o\n" +
                "\tlipo -create -output dtrace_probe.o dtrace_probe_x86_64-darwin.o dtrace_probe_i386-darwin.o"
  else
    # just selected arch
    mfile.print "dtrace_probe.o:\n\t$(CC) $(INCFLAGS) $(CXXFLAGS) -c #{arch}/dtrace_probe.c\n\n"
  end
ensure
  mfile.close
end
