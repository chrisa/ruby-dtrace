#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceProbes < Test::Unit::TestCase

  def test_is_not_enabled
    Dtrace::Provider.create :foo0 do |p|
      p.probe :bar
    end
    
    data = 'not fired'
    Dtrace::Probe::Foo0.bar do |p|
      data = 'fired'
      p.fire
    end    

    assert_equal 'not fired', data
  end

  def test_probe_no_args
    Dtrace::Provider.create :foo1 do |p|
      p.probe :bar
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo1*:ruby:test_probe_no_args:bar
{
  trace("fired");
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Foo1.bar do |p|
      p.fire
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'fired', data[0].data[0].value
    
  end
  
  def test_probe_one_int_arg
    Dtrace::Provider.create :foo2 do |p|
      p.probe :bar, :integer
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo2*:ruby:test_probe_one_int_arg:bar
{
  trace(arg0);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Foo2.bar do |p|
      p.fire(42)
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 42, data[0].data[0].value
    
  end

  def test_multiple_probes_w_args
    Dtrace::Provider.create :foo3 do |p|
      p.probe :bar, :integer
      p.probe :baz, :string
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo3*:ruby:*:bar
{
  trace(arg0);
}

foo3*:ruby:*:baz
{
  trace(copyinstr(arg0));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Foo3.bar do |p|
      p.fire(42)
    end    

    Dtrace::Probe::Foo3.baz do |p|
      p.fire('fired!')
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 2, data.length
    assert_equal 42, data[0].data[0].value
    assert_equal 'fired!', data[1].data[0].value
    
  end

  def test_multiple_probes_w_multiple_args
    Dtrace::Provider.create :foo4 do |p|
      p.probe :bar, :integer, :integer
      p.probe :baz, :string, :string
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo4*:ruby:*:bar
{
  trace(arg0);
  trace(arg1);
}

foo4*:ruby:*:baz
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Foo4.bar do |p|
      p.fire(42, 27)
    end    

    Dtrace::Probe::Foo4.baz do |p|
      p.fire('fired!', 'again')
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 2, data.length
    assert_equal 42, data[0].data[0].value
    assert_equal 27, data[0].data[1].value
    assert_equal 'fired!', data[1].data[0].value
    assert_equal 'again', data[1].data[1].value
    
  end

  def test_six_argcs
    Dtrace::Provider.create :foo5 do |p|
      p.probe :bar1, :integer
      p.probe :bar2, :integer, :integer
      p.probe :bar3, :integer, :integer, :integer
      p.probe :bar4, :integer, :integer, :integer, :integer
      p.probe :bar5, :integer, :integer, :integer, :integer,
                     :integer
      p.probe :bar6, :integer, :integer, :integer, :integer,
                     :integer, :integer
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo5*:ruby:*:bar1
{
  trace(arg0);

}

foo5*:ruby:*:bar2
{
  trace(arg0);
  trace(arg1);

}

foo5*:ruby:*:bar3
{
  trace(arg0);
  trace(arg1);
  trace(arg2);

}

foo5*:ruby:*:bar4
{
  trace(arg0);
  trace(arg1);
  trace(arg2);
  trace(arg3);

}

foo5*:ruby:*:bar5
{
  trace(arg0);
  trace(arg1);
  trace(arg2);
  trace(arg3);
  trace(arg4);
}

foo5*:ruby:*:bar6
{
  trace(arg0);
  trace(arg1);
  trace(arg2);
  trace(arg3);
  trace(arg4);
  trace(arg5);
}

EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)
    
    Dtrace::Probe::Foo5.bar1 do |p|
      p.fire(11)
    end
    Dtrace::Probe::Foo5.bar2 do |p|
      p.fire(21, 22)
    end
    Dtrace::Probe::Foo5.bar3 do |p|
      p.fire(31, 32, 33)
    end
    Dtrace::Probe::Foo5.bar4 do |p|
      p.fire(41, 42, 43, 44)
    end
    Dtrace::Probe::Foo5.bar5 do |p|
      p.fire(51, 52, 53, 54, 55)
    end
    Dtrace::Probe::Foo5.bar6 do |p|
      p.fire(61, 62, 63, 64, 65, 66)
    end

    data = []
    c.consume_once do |d|
      data << d
    end
    
    assert_equal 6, data.length

    assert_equal 11, data[0].data[0].value

    assert_equal 21, data[1].data[0].value
    assert_equal 22, data[1].data[1].value

    assert_equal 31, data[2].data[0].value
    assert_equal 32, data[2].data[1].value
    assert_equal 33, data[2].data[2].value

    assert_equal 41, data[3].data[0].value
    assert_equal 42, data[3].data[1].value
    assert_equal 43, data[3].data[2].value
    assert_equal 44, data[3].data[3].value

    assert_equal 51, data[4].data[0].value
    assert_equal 52, data[4].data[1].value
    assert_equal 53, data[4].data[2].value
    assert_equal 54, data[4].data[3].value
    assert_equal 55, data[4].data[4].value

    assert_equal 61, data[5].data[0].value
    assert_equal 62, data[5].data[1].value
    assert_equal 63, data[5].data[2].value
    assert_equal 64, data[5].data[3].value
    assert_equal 65, data[5].data[4].value
    assert_equal 66, data[5].data[5].value
    
  end

  def test_all_six_args_chars
    Dtrace::Provider.create :foo6 do |p|
      p.probe :bar, 
              :string, :string, :string, :string, :string, :string
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo6*:ruby:*:bar
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
  trace(copyinstr(arg2));
  trace(copyinstr(arg3));
  trace(copyinstr(arg4));
  trace(copyinstr(arg5));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Foo6.bar do |p|
      p.fire('one',  'two', 'three', 'four', 'five', 'six')
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'one',   data[0].data[0].value
    assert_equal 'two',   data[0].data[1].value
    assert_equal 'three', data[0].data[2].value
    assert_equal 'four',  data[0].data[3].value
    assert_equal 'five',  data[0].data[4].value
    assert_equal 'six',   data[0].data[5].value
  end
  
end
