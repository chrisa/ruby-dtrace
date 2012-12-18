require 'test_helper'

# Tests for the DTrace handle class

class TestDTrace < DTraceTest

  def test_dtrace
    assert_equal Object, DTrace.superclass
    assert_equal DTrace, @dtp.class
  end

  def test_list_probes
    probe_count = 0
    @dtp.each_probe do |probe|
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match
    probe_count = 0
    @dtp.each_probe('syscall:::') do |probe|
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match_usdt
    probe_count = 0
    @dtp.each_probe("pid#{$$}:::return") do |probe|
      puts probe
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match_prog
    progtext = "syscall:::return
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}

                syscall:::entry
                /pid == $1/
                {
                   @calls[execname] = count();
                   @fcalls[probefunc] = count();
                }"
    prog = @dtp.compile(progtext, $$.to_s)
    prog.execute

    probe_count = 0
    @dtp.each_probe_prog(prog) do |probe|
      assert probe.provider
      assert probe.mod
      assert probe.func
      assert probe.name
      probe_count += 1
    end
    assert probe_count
  end

  def test_list_probes_match_badpattern
    probe_count = 0
    assert_raises DTrace::Exception do
      @dtp.each_probe('syscall') do |probe|
        nil
      end
    end
  end

  def test_compile
    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}"

    prog = @dtp.compile progtext
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
    progtext = "syscall:::entry
                /pid == $1/
                {
                   @calls[execname] = count();
                   @fcalls[probefunc] = count();
                }"

    prog = @dtp.compile(progtext, $$.to_s)
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
    progtext = "syscall:::entry
   			{
                          @calls[execname] = count();
			  @fcalls[probefunc] = count();
			}"

    prog = @dtp.compile progtext
    assert prog
    prog.execute
    assert_equal 0, @dtp.status # none

    @dtp.go

    assert_equal 1, @dtp.status # ok
    sleep 1
    assert_equal 1, @dtp.status # ok
    @dtp.stop
    assert_equal 4, @dtp.status # stopped
  end

  def test_bad_program
    progtext = "blah blahb albhacasfas"
    e = assert_raise DTrace::Exception do
      prog = @dtp.compile progtext
    end
    assert_equal "probe description :::blah does not match any probes", e.message
  end

end
