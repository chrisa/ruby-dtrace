#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceProbes < Test::Unit::TestCase

  def test_probe_no_args
    Dtrace::Provider.create :foo1 do |p|
      p.probe :bar
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo1*:testmodule:main:bar
{
  trace("fired");
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

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
foo2*:testmodule:main:bar
{
  trace(arg0);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

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
foo3*:testmodule:main:bar
{
  trace(arg0);
}

foo3*:testmodule:main:baz
{
  trace(copyinstr(arg0));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

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
foo4*:testmodule:main:bar
{
  trace(arg0);
  trace(arg1);
}

foo4*:testmodule:main:baz
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

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

  def test_all_eight_args_integers
    Dtrace::Provider.create :foo5 do |p|
      p.probe :bar, :integer, :integer, :integer, :integer,
                    :integer, :integer, :integer, :integer
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo5*:testmodule:main:bar
{
  trace(arg0);
  trace(arg1);
  trace(arg2);
  trace(arg3);
  trace(arg4);
  trace(arg5);
  trace(arg6);
  trace(arg7);

}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)
    
    Dtrace::Probe::Foo5.bar do |p|
      p.fire(1, 2, 3, 4, 5, 6, 7, 8)
    end    

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 1, data[0].data[0].value
    assert_equal 2, data[0].data[1].value
    assert_equal 3, data[0].data[2].value
    assert_equal 4, data[0].data[3].value
    assert_equal 5, data[0].data[4].value
    assert_equal 6, data[0].data[5].value
    assert_equal 7, data[0].data[6].value
    assert_equal 8, data[0].data[7].value
    
  end

  def test_all_eight_args_chars
    Dtrace::Provider.create :foo6 do |p|
      p.probe :bar, :string, :string, :string, :string,
                    :string, :string, :string, :string
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo6*:testmodule:main:bar
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
  trace(copyinstr(arg2));
  trace(copyinstr(arg3));
  trace(copyinstr(arg4));
  trace(copyinstr(arg5));
  trace(copyinstr(arg6));
  trace(copyinstr(arg7));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

    Dtrace::Probe::Foo6.bar do |p|
      p.fire('one',  'two', 'three', 'four',
             'five', 'six', 'seven', 'eight')
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
    assert_equal 'seven', data[0].data[6].value
    assert_equal 'eight', data[0].data[7].value
    
  end

end
