#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#
# A scalar DTrace record. Its value is as set by the DTrace action
# which triggered it.
class DtraceRecord
  attr_accessor :value
end
