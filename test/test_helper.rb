require 'dtrace'
require 'test/unit'

class DTraceTest < Test::Unit::TestCase

  def setup
    @dtp = DTrace.new
    @dtp.setopt("bufsize", "4m")
    @dtp.setopt("aggsize", "4m")
  end

  def teardown
    @dtp.close unless @dtp.nil?
  end

  def test_nothing
    assert(1)
  end

end
