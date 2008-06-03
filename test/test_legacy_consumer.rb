#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests using the DTrace profile provider.

class TestLegacyConsumer < Test::Unit::TestCase
  def test_aggregate_group
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext =<<EOD
profile-1000
{ 
  @a[execname] = count();
  @b[execname] = count();
}

profile-1
{
  printa(@a);
  printa(@b);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go

    sleep 3

    c = DtraceConsumer.new(t)
    assert c

    data = []
    c.consume_once do |d|
      data << d
    end
    
    assert data.length > 0
    data.each do |d|
      assert d
      assert_equal Dtrace::Data, d.class
      d.data.each do |agg|
        assert_equal Dtrace::AggregateSet, agg.class
      end
    end

  end

end
