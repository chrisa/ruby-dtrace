#
# Ruby-Dtrace
# (c) 2009 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests for trace()d data.

class TestDtraceProbedata < Test::Unit::TestCase

  def test_longlongs

    t = Dtrace.new
    t.setopt('bufsize', '8m')

    code = <<D
profile-100
{
  trace(walltimestamp);
}
D
    t.compile(code).execute
    t.go

    c = Dtrace::Consumer.new(t)
    assert c

    i = 0
    c.consume do |d|
      wallts = d.data[0].value
      assert wallts > 2**32
      i = i + 1
      if i > 10
        c.finish
      end
    end
  end
end
