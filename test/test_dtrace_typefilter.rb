#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests for the feature allowing you to filter DtraceData types

class TestDtraceTypefilter < Test::Unit::TestCase
  def test_filter
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext =<<EOD
profile-1000
{ 
  @a[execname] = count();
  @b[execname] = count();
}

profile-10
{
  trace("foo");
  printa(@a);
  printf("bar");
  printa(@b);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go

    sleep 1

    c = DtraceConsumer.new(t)
    assert c

    data = []
    c.consume_once(DtraceAggregateSet) do |d|
      data << d
    end
    
    assert data.length > 0
    data.each do |d|
      assert d
      assert_equal DtraceData, d.class
      d.data.each do |agg|
        assert_equal DtraceAggregateSet, agg.class
      end
    end

  end

  def test_filter_two_classes
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext =<<EOD
profile-1000
{ 
  @a[execname] = count();
  @b[execname] = count();
}

profile-10
{
  trace("foo");
  printa(@a);
  printf("bar");
  printa(@b);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go

    sleep 1

    c = DtraceConsumer.new(t)
    assert c

    data = []
    c.consume_once(DtraceAggregateSet, DtracePrintfRecord) do |d|
      data << d
    end
    
    assert data.length > 0
    data.each do |d|
      assert d
      assert_equal DtraceData, d.class
      d.data.each do |r|
        if r.respond_to?(:add_aggregate)
          assert_equal DtraceAggregateSet, r.class
        else
          assert_equal DtracePrintfRecord, r.class
        end
      end
    end

  end

end
