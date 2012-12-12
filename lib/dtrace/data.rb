#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#
# The object returned from a consumer when a probe fires.  Accumulates
# records from the callbacks, and is yielded when the data is complete.
class Dtrace
  class Data
    attr_reader :data
    attr_reader :probe
    attr_reader :cpu, :indent, :prefix, :flow

    def initialize(types)
      @types = types
      @data = []
      @curraggset = nil
      @curragg    = nil
    end

    def add_data(d)
      if @types.length == 0 || @types.include?(d.class)
        @data << d
      end
    end

    def finish
      if @curraggset
        add_data(@curraggset)
        @curraggset = nil
      end
    end

    def add_recdata(rec)
      if @curraggset
        add_data(@curraggset)
        @curraggset = nil
      end
      if rec.action == "printa"
        @curraggset = Dtrace::AggregateSet.new
      end
    end

    def add_probedata(probedata)
      probedata.each_record do |p|
        add_data(p)
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

      p r

      # buf records can be empty (trace();)
      if r
        case r.class.to_s
        when Dtrace::StackRecord.to_s
          add_data(r)
        when Dtrace::Record.to_s
          add_data(r)
        when Dtrace::PrintfRecord.to_s
          add_data(r)
        when Dtrace::AggData.to_s
          if @curragg == nil
            @curragg = Dtrace::Aggregate.new
          end
          if agg = @curragg.add_record(r)
            if @curraggset
              @curraggset.add_aggregate(@curragg)
            end
            @curragg = nil
          end
        end
      end
    end

  end
end
