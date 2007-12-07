#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceProbe
  
  def to_s
    "#{provider}:#{mod}:#{func}:#{name}"
  end
  
end
    
