#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'
require 'rbconfig'

# Tests for the Dtrace "dynamic USDT" library

class TestDynUsdt < Test::Unit::TestCase

  def test_create_usdt
    Dtrace::Provider.create :test_provider_create_usdt do |p|
      p.probe :test_probe, :string
    end

    t = Dtrace.new
    t.setopt("bufsize", "4m")

    progtext = 'test_provider_create_usdt*:::test-probe { trace(copyinstr(arg0)); }'

    prog = t.compile progtext
    prog.execute
    t.go
    
    c = DtraceConsumer.new(t)
    
    Dtrace::Probe::TestProviderCreateUsdt.test_probe do |p|
      p.fire "test_argument"
    end

    i = 0
    c.consume_once do |d|
      i = i + 1
      assert d
      assert_not_nil d.probe
      assert_equal "test_provider_create_usdt#{$$.to_s}:test_provider_create_usdt.#{Config::CONFIG['DLEXT']}:test_probe:test-probe", d.probe.to_s
      assert_equal 1, d.data.length
      assert_equal "test_argument", d.data[0].value
    end
    assert_equal 1, i
  end

  def test_create_usdt_argtypes
    Dtrace::Provider.create :test_provider_create_usdt_argtypes do |p|
      p.probe :test_probe_string, :string
      p.probe :test_probe_int,    :integer
    end

    t = Dtrace.new
    t.setopt("bufsize", "4m")

    progtext = <<EOD
test_provider_create_usdt_argtypes*:::test-probe-string { trace(copyinstr(arg0)); }
test_provider_create_usdt_argtypes*:::test-probe-int    { trace(arg0);            }
EOD

    prog = t.compile progtext
    prog.execute
    t.go
    
    c = DtraceConsumer.new(t)
    
    Dtrace::Probe::TestProviderCreateUsdtArgtypes.test_probe_string do |p|
      p.fire "test_argument"
    end

    Dtrace::Probe::TestProviderCreateUsdtArgtypes.test_probe_int do |p|
      p.fire 42
    end

    i = 0
    c.consume_once do |d|
      assert d
      assert_not_nil d.probe
      if d.probe.name == 'test-probe-string'
        assert_equal "test_argument", d.data[0].value
        i = i + 1
      elsif d.probe.name == 'test-probe-int'
        assert_equal 42, d.data[0].value
        i = i + 1
      end
    end
    assert_equal 2, i
  end

  def test_create_usdt_manyargs
    Dtrace::Provider.create :test_provider_create_usdt_manyargs do |p|
      p.probe :test_probe, :string, :string, :string, :string, :string, :string, :string, :string
    end

    t = Dtrace.new
    t.setopt("bufsize", "4m")

    progtext = <<EOD
test_provider_create_usdt_manyargs*:::test-probe 
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
    
    Dtrace::Probe::TestProviderCreateUsdtManyargs.test_probe do |p|
      values_list = (0..7).map {|i| "value #{i.to_s}" }
      p.fire(*values_list)
    end

    i = 0
    c.consume_once do |d|
      i = i + 1
      assert_equal 8, d.data.length
      (0..7).each do |j|
        assert_equal "value #{j.to_s}", d.data[j].value
      end
    end
    assert_equal 1, i
  end

  def test_many_providers
    n = 50
    (1..n).each do |i|
      Dtrace::Provider.create "test_provider_create_many_providers_#{i}_nth" do |p|
        p.probe :test_probe, :string
      end
    end

    t = Dtrace.new
    i = 0
    t.each_probe do |probe|
      if probe.provider =~ /^test_provider_create_many_providers/
        i = i + 1
      end
    end

    assert_equal n, i
  end
  
  def test_unload
    Dtrace::Provider.create :unload_me do |p|
      p.probe :test_probe, :string
    end

    Dtrace::Probe::UnloadMe.test_probe do |p|
      p.fire("Testval")
    end

    t = Dtrace.new
    i = 0
    t.each_probe do |probe|
      if probe.provider =~ /^unload_me/
        i = i + 1
      end
    end
    assert_equal 1, i

    dlerror = Dtrace::Provider.unload :unload_me
    puts dlerror

    i = 0
    t.each_probe do |probe|
      if probe.provider =~ /^unload_me/
        i = i + 1
      end
    end
    assert_equal 0, i
  end
end
    
