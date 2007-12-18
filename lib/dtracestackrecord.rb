#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceStackRecord
  attr_accessor :value

  def parse(raw)
    frames = raw.split(/\n/)
    @value = frames.map {|f| f.lstrip }.select {|f| f.length > 0 }
  end

end
