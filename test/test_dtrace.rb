#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'test/unit'

# Tests for the Dtrace handle class

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

  def test_list_probes_match
    t = Dtrace.new
    probe_count = 0
    t.each_probe('syscall:::') do |probe|
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match_usdt
    t = Dtrace.new
    probe_count = 0
    t.each_probe("pid#{$$}:::return") do |probe|
      puts probe
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match_badpattern
    t = Dtrace.new
    probe_count = 0
    assert_raises Dtrace::Exception do 
      t.each_probe('syscall') do |probe|
        nil
      end
    end
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

  def test_bad_program
    t = Dtrace.new
    progtext = "blah blahb albhacasfas"
    e = assert_raise Dtrace::Exception do
      prog = t.compile progtext
    end
    assert_equal "probe description :::blah does not match any probes", e.message
  end
  
end
