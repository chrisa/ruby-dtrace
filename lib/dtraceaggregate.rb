#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceAggregate
  attr_accessor :value, :tuple

  def initialize
    @tuple = Array.new
  end

end
