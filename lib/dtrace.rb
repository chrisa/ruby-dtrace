#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace_api'
require 'dtracerecord'
require 'dtraceconsumer'
require 'dtraceaggregate'
require 'dtraceaggregateset'
require 'dtraceprobedata'
require 'dtraceprobe'
require 'dtracestackrecord'
require 'dtraceprintfrecord'
require 'dtracedata'

# A DTrace handle. Provides methods for inspecting available probes,
# compiling and running programs, and for setting up callbacks to
# receive trace data.
#
# The general structure of a Dtrace-based program is:
#
# * Create a handle with Dtrace.new
# * Set options
# * Compile the program, possibly inspecting the return DtraceProgramInfo
# * Execute the program
# * Start tracing
# * Consume data, either directly by setting up callbacks, or using a DtraceConsumer.
# * Stop tracing
#
# === Listing probes
#
#   d.each_probe do |p|
#     puts "#{p.provider}:#{p.mod}:#{p.func}:#{p.name}"
#   end
#
# === Setting options
#
#   d.setopt("bufsize", "8m")
#   d.setopt("aggsize", "4m")
#   d.setopt("stackframes", "5")
#   d.setopt("strsize", "131072")
#
# === Compiling a program
#
#   d.compile "syscall:::entry { trace(execname); stack(); }"
#   d.execute
#
# === Setting up callbacks
#
#   d.buf_consumer(prob {|buf| yield buf })
#   d.work(proc {|probe| yield probe }, proc {|rec| yield rec })
#
# === Creating a process
#
#   p = t.createprocess([ '/usr/bin/true' ])
#   t.go
#   p.continue
#
#   c = DtraceConsumer.new(t)
#   c.consume do |d|
#     ..
#   end

class Dtrace
  VERSION = '0.0.3'
end

