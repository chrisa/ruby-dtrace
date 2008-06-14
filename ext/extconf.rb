require 'mkmf'
require 'rbconfig'

def symlink(old, new)
  if File.exists?(new) && File.symlink?(new)
    File.unlink(new)
  end
  File.symlink(old, new)
end

$CFLAGS += " -D_LONGLONG_TYPE -g"
have_library("dtrace", "dtrace_open")

# Update machine-dependent symlinks in the source, based on $Config::CONFIG

cpu = Config::CONFIG['target_cpu']
os  = Config::CONFIG['target_os']

cpu.gsub! /^i[4-6]86/, 'i386'
os.gsub!  /[0-9.]+$/, ''

dir = "#{cpu}-#{os}"
symlink "#{dir}/dtrace_probe.c", "dtrace_probe.c"

# Create makefile in the usual way

create_makefile("dtrace_api")

