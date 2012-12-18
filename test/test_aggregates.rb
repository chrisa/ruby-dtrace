require 'test_helper'

class TestAggregates < DTraceTest

  def test_aggregate_group
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

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go

    sleep 3

    c = Dtrace::Consumer.new(@dtp)
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
