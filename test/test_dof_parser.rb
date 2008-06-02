#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace/dof'
require 'test/unit'

$dof_dir = File.dirname(__FILE__)

# Tests for the Dtrace DOF parser

class TestDofParser < Test::Unit::TestCase

  def test_parse
    assert File.exists?("#{$dof_dir}/dof")
    Dtrace::Dof::Parser.parse(IO.read("#{$dof_dir}/dof"))
  end

end
