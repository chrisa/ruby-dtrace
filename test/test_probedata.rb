require 'test_helper'

# Tests for trace()d data.

class TestProbedata < DTraceTest

  def test_longlongs
    code = <<D
profile-100
{
  trace(walltimestamp);
}
D
    @dtp.compile(code).execute
    @dtp.go

    c = Dtrace::Consumer.new(@dtp)
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
