#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'
require 'benchmark'

class TestDisabledProbeEffect < Test::Unit::TestCase

  def test_probe_no_args
    
    n = 20000
    Benchmark.bm do |x|
      
      x.report "noprobes:" do 
        # First time a loop with no probes created
        (1..n).each do |i|
          # no op
        end
      end
      
      x.report "disabled:" do 
        # Second time a loop with probes created but not enabled.
        Dtrace::Provider.create :dpe do |p|
          p.probe :p1
        end
        
        (1..n).each do |i|
          Dtrace::Probe::Dpe.p1 { |p| p.fire }
        end
      end
    
      x.report "enabled: " do
        # Third time a loop with probes enabled
        t = Dtrace.new 
        t.setopt("bufsize", "4m")
        
        progtext = <<EOD
dpe*:testmodule:main:p1
{
}
EOD
        
        prog = t.compile progtext
        prog.execute
        t.go
        
        (1..n).each do |i|
          Dtrace::Probe::Dpe.p1 { |p| p.fire }
        end
      end
    end

    assert 1

  end
end
