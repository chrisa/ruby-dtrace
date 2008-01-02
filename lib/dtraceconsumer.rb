#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# A DtraceConsumer provides access to the data produced by the running
# D program. Having compiled and executed a D program, you typically
# create a DtraceConsumer, and wait for data. 
#
# You can either wait indefinitely for data, or consume all the data
# waiting and then stop: if your D program consists of only of
# aggregations, returned by printa() actions in the END block, this
# will be the best approach. If you have a mix of trace() and print()
# actions elsewhere, you'll probably want to wait until interrupted,
# the D program itself exits, or your program decides it has collected
# enough data.
#
# The two approaches are implemented by the +consume+ and
# +consume_once+ methods.
#
# The objects returned are of the following classes, depending on the
# actions fired:
#
# * DtraceRecord
# * DtraceAggregate
# * DtraceStackRecord
#
# You must have already started tracing when you call +consume+ or
# +consume_once+, so the general structure will look like:
#
#   t = Dtrace.new
#   progtext = "..."
#   prog = t.compile progtext
#   prog.execute
#   t.go 
#   c = DtraceConsumer.new(t)
#   c.consume_once do |r|
#     # handle records
#   end

class DtraceConsumer

  def initialize(t)
    @t = t
    @curragg = DtraceAggregate.new
  end

  private
  
  def probe_consumer(block)
    proc do |probe|
      # Handle multiple records in each Probedata
      probe.each_record do |rec|
        block.call(rec)
      end
    end
  end

  def buf_consumer(block)
    proc do |buf|
      r = buf.record
      # buf records can be empty (trace();)
      if r 
        case r.class.to_s
        when DtraceStackRecord.to_s
          block.call(r)
        when DtraceRecord.to_s
          block.call(r)
        when DtraceAggData.to_s
          if agg = @curragg.add_record(r)
            block.call(agg)
            @curragg = DtraceAggregate.new
          end
        end
      end
    end
  end
  
  public
  
  # Waits for data from the D program, and yields the records returned
  # to the block given. Returns when the D program exits.
  def consume(&block)
    @t.buf_consumer(buf_consumer(block))
    begin
      while(true) do
        @t.sleep
        @t.work(probe_consumer(block))
      end
    ensure
      @t.stop
      @t.work(probe_consumer(block))
    end
  end
  
  # Yields the data waiting from the current program, then returns.
  def consume_once(&block)
    @t.buf_consumer(buf_consumer(block))
    @t.stop
    @t.work(probe_consumer(block))
  end
  
end

