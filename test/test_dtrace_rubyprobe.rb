require 'dtrace'
require 'test/unit'
require 'pp'

class TestDtrace < Test::Unit::TestCase
  def test_rubyprobe
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
ruby*:::ruby-probe
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go

    c = DtraceConsumer.new(t)

    begin
      trace_module = DTracer
    end

    (0..9).each do |i|
      trace_module.fire("foo", i.to_s) # { raise }
    end

    data = []
    c.consume_once do |d|
      pp d
      data << d
    end
    
    (0..9).each do |i|
      d = data.shift
      assert_equal("foo-start", d.data[0].value)
      assert_equal(i.to_s, d.data[1].value)
      d = data.shift
      assert_equal("foo-end", d.data[0].value)
      assert_equal(i.to_s, d.data[1].value)
    end

  end
    
end
