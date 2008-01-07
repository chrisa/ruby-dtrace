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

}
EOD

    p = t.createprocess([ '/usr/bin/true' ])
    prog = t.compile(progtext)
    prog.execute
    t.go
    p.continue

    i = 0
    c = DtraceConsumer.new(t)
    c.consume do |d|
      assert d
      i = i + 1
      if i > 10
        break
      end
    end

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

    p = t.grabprocess(1)

    prog = t.compile(progtext)
    prog.execute

    t.go
    p.continue

    c = DtraceConsumer.new(t)
    c.consume_once do |d|
      assert d
    end

  end
end
