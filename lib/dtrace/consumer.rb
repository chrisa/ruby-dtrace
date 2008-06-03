#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# A Dtrace::Consumer provides access to the data produced by the running
# D program. Having compiled and executed a D program, you typically
# create a Dtrace::Consumer, and wait for data. 
#
# You can either wait indefinitely for data, or consume all the data
# waiting and then stop: if your D program consists of only of
# aggregations, returned by printa() actions in the END block, this
# will be the best approach. If you have a mix of trace() and printf()
# actions elsewhere, you'll probably want to wait until interrupted,
# the D program itself exits, or your program decides it has collected
# enough data.
#
# The two approaches are implemented by the +consume+ and
# +consume_once+ methods.
#
# The +consume+ and +consume_once+ methods accept a block to which is
# yielded complete Dtrace::Data objects, one for each probe which fires.
#
# You must have already started tracing when you call +consume+ or
# +consume_once+, so the general structure will look like:
#
#   t = Dtrace.new
#   progtext = "..."
#   prog = t.compile progtext
#   prog.execute
#   t.go 
#   c = Dtrace::Consumer.new(t)
#   c.consume_once do |d|
#     # handle Dtrace::Data objects
#     # ...
#     # get bored:
#     c.finish
#   end

class Dtrace
  class Consumer

    def initialize(t)
      @t = t
      @done = false
      @types = []

      @drophandler = nil
      @errhandler = nil
    end

    private

    # The consumer callbacks:
    #
    # DtraceRecDesc   -> rec_consumer
    # DtraceProbeData -> probe_consumer
    # DtraceBufData   -> buf_consumer
    #
    # We expect a sequence of calls to these procs, and we accumulate
    # data in the @curr Dtrace::Data based on this:
    #
    # Dtrace::ProbeData (initial callback for a probe firing)
    # Dtrace::RecDesc 
    # ...
    # Dtrace::RecDesc = nil (end of data)
    #
    
    def rec_consumer(block)
      proc do |rec|
        if rec
          @curr.add_recdata(rec)
        else
          @curr.finish
          block.call(@curr)
          @curr = Dtrace::Data.new(@types)
        end
      end
    end
    
    def probe_consumer
      proc do |probe|
        @curr.add_probedata(probe)
      end
    end

    def buf_consumer
      proc do |buf|
        @curr.add_bufdata(buf)
      end
    end

    def filter_types(types)
      @types = types
      @curr = Dtrace::Data.new(types)
    end
    
    public

    # Provide a proc which will be executed when a drop record is
    # received.
    def drophandler(&block)
      @drophandler = block
      @t.drop_consumer(proc do |drop|
                         if @drophandler
                           @drophandler.call(drop)
                         end
                       end)
    end

    # Provide a proc which will be executed when an error record is
    # received.
    def errhandler(&block)
      @errhandler = block
      @t.err_consumer(proc do |err|
                        if @errhandler
                          @errhandler.call(err)
                        end
                      end)
    end

    # Signals that the client wishes to stop consuming trace data. 
    def finish
      @t.stop
      @done = true
    end
    
    # Waits for data from the D program, and yields the records returned
    # to the block given. Returns when the D program exits.
    #
    # Pass a list of classes to restrict the types of data returned,
    # from:
    #
    # * DtraceRecord
    # * DtracePrintfRecord
    # * DtraceAggregateSet
    # * DtraceStackRecord
    #
    def consume(*types, &block)
      filter_types(types)
      @t.buf_consumer(buf_consumer)
      begin
        while(true) do
          @t.sleep
          work = @t.work(probe_consumer, rec_consumer(block))
          if (@done || work > 0)
            break
          end
        end
      ensure
        @t.stop
        @t.work(probe_consumer)
      end
    end
    
    # Yields the data waiting from the current program, then returns.
    #
    # Pass a list of classes to restrict the types of data returned,
    # from:
    #
    # * DtraceRecord
    # * DtracePrintfRecord
    # * DtraceAggregateSet
    # * DtraceStackRecord
    #
    def consume_once(*types, &block)
      filter_types(types)
      @t.buf_consumer(buf_consumer)
      @t.stop
      @t.work(probe_consumer, rec_consumer(block))
    end
    
  end
end
