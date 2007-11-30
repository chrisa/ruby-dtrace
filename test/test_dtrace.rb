#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

class TestDtrace < Test::Unit::TestCase
  def test_dtrace
    t = Dtrace.new
    assert_equal Object, Dtrace.superclass
    assert_equal Dtrace, t.class
  end

  def test_list_probes
    t = Dtrace.new
    probe_count = 0
    t.each_probe do |probe|
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_compile
    t = Dtrace.new

    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute

    info = prog.info
    assert info
    assert info.aggregates_count
    assert_equal 0, info.speculations_count
    assert info.recgens_count
    assert info.matches_count
  end
  
  def test_compile_with_args
    t = Dtrace.new

    progtext = "syscall:::entry
                /pid == $1/
                {
                   @calls[execname] = count();
                   @fcalls[probefunc] = count();
                }"

    prog = t.compile(progtext, $$.to_s)
    assert prog
    prog.execute

    info = prog.info
    assert info
    assert_equal 2,   info.aggregates_count
    assert_equal 0,   info.speculations_count
    assert_equal 4,   info.recgens_count
    
    # matches_count is platform dependent
    assert info.matches_count
  end
      
  def test_run
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute
    assert_equal 0, t.status # none

    t.go

    assert_equal 1, t.status # ok
    sleep 1
    assert_equal 1, t.status # ok
    t.stop
    assert_equal 4, t.status # stopped
  end

  def test_aggregate_print
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go
    sleep 1
    t.stop

    t.aggregate_snap
    t.aggregate_print
  end

  def test_aggregate_walk
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   			{
			  @fcalls[probefunc] = count();
                          @calls[execname] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go
    sleep 1
    t.stop

    t.aggregate_snap
    
    t.each_aggregate do |agg|
      agg.each_record do |rec|
        assert rec
        assert rec.data
      end
    end
  end

  def test_aggregate_record_array
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go
    sleep 1
    t.stop

    t.aggregate_snap
    
    t.each_aggregate do |agg|
      assert agg
      assert agg.num_records
      (0..(agg.num_records - 1)).each do |i|
        rec = agg[i]
        assert rec.data
      end
    end
  end

  def test_aggregate_record_array_continuous
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			}"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go

    (1..10).each do 
      sleep 1
      t.aggregate_snap
      
      t.each_aggregate do |agg|
        assert agg
        assert agg.num_records
        (0..(agg.num_records - 1)).each do |i|
          rec = agg[i]
          assert rec.data
        end
      end
      t.aggregate_clear
    end

    t.stop
  end

  def test_bad_program
    t = Dtrace.new
    progtext = "blah blahb albhacasfas"
    e = assert_raise DtraceException do
      prog = t.compile progtext
    end
    assert_equal "probe description :::blah does not match any probes", e.message
  end

  def test_rubys_own_dtrace
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "ruby*:::function-entry{ @[copyinstr(arg1)] = count(); }"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go

    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end
    
    t.stop
    t.aggregate_snap
    
    t.each_aggregate do |agg|
      assert agg
      assert agg.num_records
      (0..(agg.num_records - 1)).each do |i|
        rec = agg[i]
        assert rec.data
      end
    end
  end

  def test_multiple_programs
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "syscall:::entry
   		{
                    @calls[execname] = count();
                }"

    prog1 = t.compile progtext
    assert prog1

    progtext = "syscall:::entry
   		{
			  @fcalls[probefunc] = count();
                }"

    prog2 = t.compile progtext
    assert prog2

    prog1.execute
    prog2.execute

    info1 = prog1.info
    assert info1
    assert_equal 1,   info1.aggregates_count
    assert_equal 0,   info1.speculations_count
    assert_equal 2,   info1.recgens_count
    assert            info1.matches_count

    info2 = prog2.info
    assert info2
    assert_equal 1,   info2.aggregates_count
    assert_equal 0,   info2.speculations_count
    assert_equal 2,   info2.recgens_count
    assert            info2.matches_count

    t.go
    sleep 2
    t.stop
    t.aggregate_snap
    
    t.each_aggregate do |agg|
      assert agg
      assert agg.num_records
      (0..(agg.num_records - 1)).each do |i|
        rec = agg[i]
        assert rec.data
      end
    end
  end

  def test_multiple_runs
    t = Dtrace.new
    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "ruby*:::function-entry{ @[copyinstr(arg1)] = count(); }"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go

    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end
    
    t.stop
    t.aggregate_snap
    
    t.each_aggregate do |agg|
      assert agg
      assert agg.num_records
      (0..(agg.num_records - 1)).each do |i|
        rec = agg[i]
        assert rec.data
      end
    end

    t = Dtrace.new
    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    prog = t.compile progtext
    assert prog

    prog.execute

    t.go

    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end
    
    t.stop
    t.aggregate_snap
    
    t.each_aggregate do |agg|
      assert agg
      assert agg.num_records
      (0..(agg.num_records - 1)).each do |i|
        rec = agg[i]
        assert rec.data
      end
    end

  end

  def test_aggdata_probe
    t = Dtrace.new

    t.setopt("aggsize", "4m")
    t.setopt("bufsize", "4m")

    progtext = "ruby*:::function-entry{ @[copyinstr(arg1)] = count(); }"

    prog = t.compile progtext
    assert prog
    prog.execute

    t.go

    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end

    t.stop

    t.aggregate_snap
    
    t.each_aggregate do |agg|

      probe = agg.probe
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      
      agg.each_record do |rec|
        assert rec
        assert rec.data
      end
    end


  end
  
end
