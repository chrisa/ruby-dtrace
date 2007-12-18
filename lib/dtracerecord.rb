#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceRecord
  attr_accessor :value

  def to_s
    value
  end
end
