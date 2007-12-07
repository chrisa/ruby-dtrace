#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceConsumer

  def initialize(t)
    @t = t
    @curragg = DtraceAggregate.new
  end

  def consume

    probe_consumer = proc do |probe|
      yield probe
    end
    
    rec_consumer = proc do |rec|
      #yield rec
    end
    
    buf_consumer = proc do |buf|
      r = buf.record
      # buf records can be empty (trace();)
      if r 
        case r.class.to_s
        when DtraceRecord.to_s
          yield r
        when DtraceAggData.to_s
          case r.aggtype
          when "tuple"
            @curragg.tuple << r.value
          when "value"
            @curragg.value = r.value
          when "last"
            yield @curragg
            @curragg = DtraceAggregate.new
          end

        end
      end
    end    
  
    @t.go
    @t.buf_consumer(buf_consumer)
    begin
      while(true) do
        @t.sleep
        @t.work(probe_consumer, rec_consumer)
      end
    ensure
      @t.stop
      @t.work(probe_consumer, rec_consumer)
    end
    
  end
  
  def consume_once
    
    probe_consumer = proc do |probe|
      probe.each_record do |r|
        yield r
      end
    end
    
    rec_consumer = proc do |rec|
      #yield rec
    end
    
    buf_consumer = proc do |buf|
      r = buf.record
      # buf records can be empty (trace();)
      if r 
        case r.class.to_s
        when DtraceRecord.to_s
          yield r
        when DtraceAggData.to_s
          case r.aggtype
          when "tuple"
            @curragg.tuple << r.value
          when "value"
            @curragg.value = r.value
          when "last"
            yield @curragg
            @curragg = DtraceAggregate.new
          end

        end
      end
    end
  
    @t.buf_consumer(buf_consumer)
    @t.stop
    @t.work(probe_consumer, rec_consumer)
  end
  
end

