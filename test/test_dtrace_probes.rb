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

    p data

    assert_equal 1, data.length
    assert_equal 42, data[0].data[0].value
    
  end

end
