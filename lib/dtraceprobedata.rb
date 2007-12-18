#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class DtraceProbeData

  def records
    records = Array.new
    self.each_record do |rec|
      records << rec
    end
    records
  end

  def to_s
    rs = self.records
    rs.map {|r| r.value }.join ', '
  end

end
