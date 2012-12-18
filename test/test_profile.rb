require 'test_helper'

# Tests using the DTrace profile provider.

class TestProfile < DTraceTest

  def test_dprogram_run
    progtext = 'profile:::profile-1 { trace("foo"); }'

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    c = Dtrace::Consumer.new(@dtp)
    assert c

    i = 0
    c.consume do |d|
      assert d
      assert_equal "profile:::profile-1", d.probe.to_s
      assert_not_nil d.cpu

      d.data.each do |r|
        assert_equal r.value, "foo"
      end

      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_dprogram_aggregate
    progtext = <<EOD
profile-1000
{
  @a[execname] = count();
}

profile-10
{
  printa(@a)
}
EOD

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    c = Dtrace::Consumer.new(@dtp)

    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-10", d.probe.to_s

      d.data.each do |r|
        assert_equal Dtrace::AggregateSet, r.class
        r.data.each do |a|
          assert_not_nil a.value
          assert_not_nil a.tuple
          assert_equal 1, a.tuple.length
        end
      end

      i = i + 1
      if i >= 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_dprogram_printf
    progtext = <<EOD
profile-1
{
  printf("execname: %s %s", execname, "foo")
}
EOD

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    c = Dtrace::Consumer.new(@dtp)

    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-1", d.probe.to_s

      i = i + 1
      if i >= 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_dprogram_aggregate_once
    progtext = <<EOD
profile-1000hz
{
  @a[execname] = count();
}

END
{
  printa(@a)
}
EOD

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    i = 0
    c = Dtrace::Consumer.new(@dtp)
    c.consume_once do |d|
      i = i + 1
      assert d
      assert_not_nil d.cpu
      assert_equal "dtrace:::END", d.probe.to_s

      d.data.each do |r|
        assert_equal Dtrace::AggregateSet, r.class
        r.data.each do |a|
          assert_not_nil a.value
          assert_not_nil a.tuple
          assert_equal 1, a.tuple.length
        end
      end
    end
    assert i > 0
  end

  def test_stack
    progtext = "profile-1 { trace(execname); stack(); }"
    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    c = Dtrace::Consumer.new(@dtp)
    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-1", d.probe.to_s

      assert_equal 2, d.data.length
      assert_equal Dtrace::Record, d.data[0].class
      assert_equal Dtrace::StackRecord, d.data[1].class

      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_ustack
    progtext = "profile-1 { trace(execname); ustack(); }"
    prog = @dtp.compile progtext
    prog.execute
    @dtp.go
    sleep 2

    c = Dtrace::Consumer.new(@dtp)
    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-1", d.probe.to_s

      assert_equal 2, d.data.length
      assert_equal Dtrace::Record, d.data[0].class
      assert_equal Dtrace::StackRecord, d.data[1].class

      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

end
