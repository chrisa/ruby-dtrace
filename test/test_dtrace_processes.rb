#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests for creating and grabbing processes.

class TestDtraceProcesses < Test::Unit::TestCase

  def test_createprocess

    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = <<EOD
pid$target:*::entry,
pid$target:*::return
{
  trace(pid);
}
EOD

    p = t.createprocess([ '/usr/bin/true' ])
    prog = t.compile(progtext)
    prog.execute
    t.go
    p.continue

    i = 0
    c = Dtrace::Consumer.new(t)
    c.consume do |d|
      assert d
      assert_equal "pid#{d.data[0].value}", d.probe.provider
      i = i + 1
      if i > 10
        c.finish
      end
    end
    assert i > 0
  end

  def test_grabprocess

    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = <<EOD
pid$target:*::entry,
pid$target:*::return
{

}
EOD

    pid = Kernel.fork { (0..9).each do sleep 1 end }
    p = t.grabprocess(pid)
    prog = t.compile(progtext)
    prog.execute

    t.go
    p.continue

    sleep 3

    i = 0
    c = Dtrace::Consumer.new(t)
    c.consume_once do |d|
      assert d
      assert_equal "pid#{pid}", d.probe.provider
      i = i + 1
    end
    assert i > 0
  end
end
