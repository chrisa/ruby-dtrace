#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# Represents an aggregation record built from a series of
# DtraceAggData records.
#
# Intended to to built up by calling +add_record+ repeatedly with
# DtraceAggData objects until a completed DtraceAggregate is returned.
# (until a complete record is available, +add_record+ returns nil).
#
# See dtraceconsumer.rb for an example of this.
class DtraceAggregate
  attr_reader :value, :tuple

  # Create an empty DtraceAggregate: use +add_record+ to add data.
  def initialize
    @tuple = Array.new
  end
  
  # Add a DtraceAggData record to this aggregate. Returns nil until it
  # receives a record of aggtype "last", when it returns the complete
  # DtraceAggregate.
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
