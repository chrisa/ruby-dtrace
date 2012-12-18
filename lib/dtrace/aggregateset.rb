#
# Ruby-DTrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DTrace
  class AggregateSet
    attr_reader :data

    def initialize
      @data = Array.new
    end
    
    def add_aggregate(agg)
      @data << agg
    end
    
  end
end
