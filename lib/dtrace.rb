#
# Ruby-DTrace
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
require 'dtrace/version'

# A DTrace handle. Provides methods for inspecting available probes,
# compiling and running programs, and for setting up callbacks to
# receive trace data.
#
# The general structure of a DTrace-based program is:
#
# * Create a handle with DTrace.new
# * Set options
# * Compile the program, possibly inspecting the return DTrace::ProgramInfo
# * Execute the program
# * Start tracing
# * Consume data, either directly by setting up callbacks, or using a DTrace::Consumer.
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
#   c = DTrace::Consumer.new(t)
#   c.consume do |d|
#     ..
#   end

class DTrace
  STATUS_NONE    = 0
  STATUS_OKAY    = 1
  STATUS_EXITED  = 2
  STATUS_FILLED  = 3
  STATUS_STOPPED = 4

  # Yields each probe on the system, optionally matching against a
  # probe specification:
  # 
  # e.g.
  # syscall:::      -> all probes in the syscall provider
  # pid123:::return -> all return probes in pid 123.
  #
  def each_probe(match=nil, &block)
    if match
      parts = match.split(':', 4)
      begin
        each_probe_match(*parts, &block)
      rescue ArgumentError => e
        raise DTrace::Exception.new("each_probe: probe specification expected (e.g. 'provider:::')")
      end
    else
      each_probe_all(&block)
    end
  end

end

