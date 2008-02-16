#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

# Tests for the Dtrace "dynamic USDT" library

class TestDynUsdt < Test::Unit::TestCase
  def test_create_usdt

    Dtrace::Provider.create :test_provider do |p|
      p.probe :test_probe, :string
    end

    t = Dtrace.new
    t.setopt("bufsize", "4m")

    progtext = 'test_provider$1:::test-probe { trace(copyinstr(arg0)); }'
    prog = t.compile progtext, $$.to_s
    prog.execute
    t.go
    
    c = DtraceConsumer.new(t)
    
    Dtrace::Probe::TestProvider.test_probe do |p|
      p.fire "test_argument"
    end

    i = 0
    c.consume_once do |d|
      i = i + 1
      assert d
      assert_not_nil d.probe
      assert_equal "test_provider#{$$.to_s}:test_provider.bundle:test_probe:test-probe", d.probe.to_s
      assert_equal 1, d.data.length
      assert_equal "test_argument", d.data[0].value
    end
    assert_equal 1, i
    
  end
end
    
