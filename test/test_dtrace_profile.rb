#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests using the DTrace profile provider.

class TestDtraceProfile < Test::Unit::TestCase
  
  def test_dprogram_run
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = 'profile:::profile-1 { trace("foo"); }'
    
    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2

    c = DtraceConsumer.new(t)
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
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

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

    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2

    c = DtraceConsumer.new(t)

    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-10", d.probe.to_s

      d.data.each do |r|
        assert_equal DtraceAggregateSet, r.class
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
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = <<EOD
profile-1
{ 
  printf("execname: %s %s", execname, "foo")
}
EOD

    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2
    
    c = DtraceConsumer.new(t)

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
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

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

    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2
    
    i = 0
    c = DtraceConsumer.new(t)
    c.consume_once do |d|
      i = i + 1
      assert d
      assert_not_nil d.cpu
      assert_equal "dtrace:::END", d.probe.to_s
      
      d.data.each do |r|
        assert_equal DtraceAggregateSet, r.class
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
    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = "profile-1 { trace(execname); stack(); }"
    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2

    c = DtraceConsumer.new(t)
    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-1", d.probe.to_s

      assert_equal 2, d.data.length
      assert_equal DtraceRecord, d.data[0].class
      assert_equal DtraceStackRecord, d.data[1].class
      
      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_ustack
    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = "profile-1 { trace(execname); ustack(); }"
    prog = t.compile progtext
    prog.execute
    t.go
    sleep 2

    c = DtraceConsumer.new(t)
    i = 0
    c.consume do |d|
      assert d
      assert_not_nil d.cpu
      assert_equal "profile:::profile-1", d.probe.to_s

      assert_equal 2, d.data.length
      assert_equal DtraceRecord, d.data[0].class
      assert_equal DtraceStackRecord, d.data[1].class

      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

end  
