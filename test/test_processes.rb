require 'test_helper'

# Tests for creating and grabbing processes.

class TestDtraceProcesses < DTraceTest

  def test_createprocess
    progtext = <<EOD
pid$target:*::entry,
pid$target:*::return
{
  trace(pid);
}
EOD

    p = @dtp.createprocess([ '/usr/bin/true' ])
    prog = @dtp.compile(progtext)
    prog.execute
    @dtp.go
    p.continue

    i = 0
    c = Dtrace::Consumer.new(@dtp)
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
    pid = Kernel.fork { exec '/bin/sleep', '2' }

    progtext = <<EOD
pid$target:::entry,
pid$target:::return
{
  trace(execname);
}
EOD

    p = @dtp.grabprocess(pid)
    prog = @dtp.compile(progtext)
    prog.execute

    @dtp.go
    p.continue

    records = 0
    c = Dtrace::Consumer.new(@dtp)
    c.consume do |d|
      assert d
      assert_equal "pid#{pid}", d.probe.provider
      records = records + 1
      c.finish
    end
    assert records > 0

    Process.waitpid(pid, 0)
  end
end
