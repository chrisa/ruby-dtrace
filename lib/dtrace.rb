#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace_api'
require 'dtrace/record'
require 'dtrace/consumer'
require 'dtraceconsumer'
require 'dtrace/aggregate'
require 'dtrace/aggregateset'
require 'dtrace/probedata'
require 'dtrace/probedesc'
require 'dtrace/stackrecord'
require 'dtrace/printfrecord'
require 'dtrace/data'

# A DTrace handle. Provides methods for inspecting available probes,
# compiling and running programs, and for setting up callbacks to
# receive trace data.
#
# The general structure of a Dtrace-based program is:
#
# * Create a handle with Dtrace.new
# * Set options
# * Compile the program, possibly inspecting the return Dtrace::ProgramInfo
# * Execute the program
# * Start tracing
# * Consume data, either directly by setting up callbacks, or using a Dtrace::Consumer.
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
#   c = Dtrace::Consumer.new(t)
#   c.consume do |d|
#     ..
#   end

class Dtrace
  VERSION = '0.2.0'

  STATUS_NONE    = 0
  STATUS_OKAY    = 1
  STATUS_EXITED  = 2
  STATUS_FILLED  = 3
  STATUS_STOPPED = 4
end

