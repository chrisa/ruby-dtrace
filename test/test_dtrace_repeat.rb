#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Test repeatedly using DTrace in the same process.  Show that we can
# reopen the DTrace handle multiple times, without explictly closing
# it (that happens in GC, so in this script that's probably right at
# the end).

class TestDtraceRepeat < Test::Unit::TestCase
  
  def test_repeats
    (0..9).each do |i|
      t = Dtrace.new 
      t.setopt("bufsize", "4m")
      t.setopt("aggsize", "4m")

      progtext = 'syscall:::entry { trace("foo"); }'
      
      prog = t.compile progtext
      prog.execute
      t.go
      
      # Let some activity happen.
      sleep 1

      c = DtraceConsumer.new(t)
      assert c

      i = 0
      c.consume do |d|
        assert d
        assert_not_nil d.cpu
        assert_equal 'syscall', d.probe.provider
        assert_not_nil d.probe.func
        assert_equal 'entry', d.probe.name

        d.data.each do |r|
          assert_equal 'foo', r.value
        end
        c.finish
        i = i + 1
      end
      assert i > 0
    end
  end
end
