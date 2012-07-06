#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/provider'
require 'test/unit'

class TestDtraceMultiProvider < Test::Unit::TestCase

  def test_multiple_providers_and_list
    Dtrace::Provider.create :multi1 do |p|
      p.probe :test1, :integer, :integer
      p.probe :test2, :integer, :integer
    end

    Dtrace::Provider.create :multi2 do |p|
      p.probe :test1, :integer, :integer
      p.probe :test2, :integer, :integer
    end

    matches = Hash.new
    matches[:multi1] = 0
    matches[:multi2] = 0

    t = Dtrace.new
    t.each_probe(":ruby::") do |p|
      if p.to_s =~ /^multi1#{$$}:ruby:/
        matches[:multi1] += 1
      end
      if p.to_s =~ /^multi2#{$$}:ruby:/
        matches[:multi2] += 1
      end
    end
    assert_equal 2, matches[:multi1]
    assert_equal 2, matches[:multi2]
  end

  def test_multiple_providers_and_fire
    Dtrace::Provider.create :multi3 do |p|
      p.probe :test3, :integer, :integer
    end

    Dtrace::Provider.create :multi4 do |p|
      p.probe :test4, :integer, :integer
    end

    progtext = <<EOD
multi3*:ruby::test3
{
  trace("fired 1");
}

multi4*:ruby::test4
{
  trace("fired 2");
}
EOD

    t = Dtrace.new
    t.setopt("bufsize", "4m")
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    Dtrace::Probe::Multi3.test3 do |p|
      p.fire(3,4)
    end

    Dtrace::Probe::Multi4.test4 do |p|
      p.fire(4,4)
    end

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 2, data.length
    assert_equal 'fired 1', data[0].data[0].value
    assert_equal 'fired 2', data[1].data[0].value
  end

end

