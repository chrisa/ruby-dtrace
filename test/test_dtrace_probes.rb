#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceProbes < Test::Unit::TestCase

  def test_probe_no_args
    Dtrace::Provider.create :foo do |p|
      p.probe :bar
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo*:testmodule:main:bar
{
  trace("fired");
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

    Dtrace::Probe::Foo.bar do |p|
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
    Dtrace::Provider.create :foo do |p|
      p.probe :bar, :int
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo*:testmodule:main:bar
{
  trace(arg0);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

    Dtrace::Probe::Foo.bar do |p|
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
    Dtrace::Provider.create :foo do |p|
      p.probe :bar, :int
      p.probe :baz, :string
    end
    
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
foo*:testmodule:main:bar
{
  trace(arg0);
}

foo*:testmodule:main:baz
{
  trace(copyinstr(arg0));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

    Dtrace::Probe::Foo.bar do |p|
      p.fire(42)
    end    

    Dtrace::Probe::Foo.baz do |p|
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

end
