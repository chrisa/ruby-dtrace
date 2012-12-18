#
# Ruby-DTrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# Represents an aggregation record built from a series of
# DTraceAggData records.
#
# Intended to to built up by calling +add_record+ repeatedly with
# DTrace::AggData objects until a completed DTrace::Aggregate is
# returned.  (until a complete record is available, +add_record+
# returns nil).
#
# See consumer.rb for an example of this.
class DTrace
  class Aggregate
    attr_reader :value, :tuple

    # Create an empty DTrace::Aggregate: use +add_record+ to add data.
    def initialize
      @tuple = Array.new
    end
    
    # Add a DTrace::AggData record to this aggregate. Returns nil until it
    # receives a record of aggtype "last", when it returns the complete
    # DTrace::Aggregate.
    def add_record(r)
      case r.aggtype
      when "tuple"
        @tuple << r.value
      when "value"
        @value = r.value
      when "last"
        return self
      end
      nil
    end

  end
end
