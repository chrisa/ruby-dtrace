#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'
require 'pp'

$dof_dir = File.dirname(__FILE__)

class TestDofHelper < Test::Unit::TestCase
  
  def test_sun_dof
    dof = File.read("#{$dof_dir}/dof")
    Dtrace.loaddof(dof)

    t = Dtrace.new
    t.each_probe do |p|
      pp p
    end
        
  end
end
