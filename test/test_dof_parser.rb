#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace/dof'
require 'test/unit'
require 'pp'

$dof_dir = File.dirname(__FILE__)

# Tests for the Dtrace DOF parser

class TestDofParser < Test::Unit::TestCase

  def test_parse
    assert File.exists?("#{$dof_dir}/dof")
    dof = IO.read("#{$dof_dir}/dof")
    d = Dtrace::Dof::Parser.parse(dof)
    pp d
  end

  def test_parse2
    assert File.exists?("#{$dof_dir}/dof2")
    dof = IO.read("#{$dof_dir}/dof2")
    d = Dtrace::Dof::Parser.parse(dof)
    pp d
  end
end
