require 'test_helper'

# Tests for the feature allowing you to filter DtraceData types

class TestTypefilter < DTraceTest
  def test_filter
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

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go

    sleep 1

    c = Dtrace::Consumer.new(@dtp)
    assert c

    data = []
    c.consume_once(Dtrace::AggregateSet) do |d|
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

  def test_filter_two_classes
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

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go

    sleep 1

    c = Dtrace::Consumer.new(@dtp)
    assert c

    data = []
    c.consume_once(Dtrace::AggregateSet, Dtrace::PrintfRecord) do |d|
      data << d
    end

    assert data.length > 0
    data.each do |d|
      assert d
      assert_equal Dtrace::Data, d.class
      d.data.each do |r|
        if r.respond_to?(:add_aggregate)
          assert_equal Dtrace::AggregateSet, r.class
        else
          assert_equal Dtrace::PrintfRecord, r.class
        end
      end
    end

  end

end
