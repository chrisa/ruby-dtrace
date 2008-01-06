#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#
# The object returned from a consumer when a probe fires.  Accumulates
# records from the callbacks, and is yielded when the data is complete.
class DtraceData
  attr_reader :data

  def initialize
    @data = []
  end

  def add_probedata(probedata)
    probedata.each_record do |p|
      @data << p
    end

    # Record the probe that fired, and CPU/indent/prefix/flow
    @probe  = probedata.probe
    @cpu    = probedata.cpu
    @indent = probedata.indent
    @prefix = probedata.prefix
    @flow   = probedata.flow
  end

  def add_bufdata(buf)
    r = buf.record
    # buf records can be empty (trace();)
    if r
      case r.class.to_s
      when DtraceStackRecord.to_s
        @data << r
      when DtraceRecord.to_s
        @data << r
      when DtraceAggData.to_s
        if @curragg == nil
          @curragg = DtraceAggregate.new
        end
        if agg = @curragg.add_record(r)
          @data << @curragg
          @curragg = DtraceAggregate.new
        end
      end
    end
  end
  
end
