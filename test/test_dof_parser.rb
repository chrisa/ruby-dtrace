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
    flunk
    assert File.exists?("#{$dof_dir}/dof")
    dof = Dtrace::Dof::Parser.parse(IO.read("#{$dof_dir}/dof"))
  end

  def test_parse_apple_dof
    flunk
    assert File.exists?("#{$dof_dir}/apple-dof")
    dof = Dtrace::Dof::Parser.parse(IO.read("#{$dof_dir}/apple-dof"))
  end

end
