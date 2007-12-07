require 'dtrace'
require 'test/unit'

class TestDtrace < Test::Unit::TestCase
  def test_dtrace
    t = Dtrace.new
    assert t
    assert_equal Object, Dtrace.superclass
    assert_equal Dtrace, t.class
  end

  def test_work_dprogram_compile
    t = Dtrace.new 
    assert t

    progtext = "syscall::select:entry { trace(probefunc); trace(execname); }"

    prog = t.compile progtext
    assert prog
    prog.execute

    info = prog.info
    assert info
    assert_equal 1, info.matches_count
  end

  def test_work_dprogram_run
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = "syscall:::entry { trace(probefunc); trace(execname); }"
    
    prog = t.compile progtext
    prog.execute

    c = DtraceConsumer.new(t)
    assert c

    begin
      i = 0
      c.consume do |e|
        assert e
        assert e.probedesc
        assert_equal 'syscall', e.probedesc.provider
        assert_equal 'entry', e.probedesc.name
        records = e.records
        assert records
        assert_equal 2, records.length
        assert_equal DtraceRecord, records[0].class
        assert_equal DtraceRecord, records[1].class

        i = i + 1
        if i > 10
          break
        end
      end
    rescue Interrupt
      puts "interrupted"
    end
  end

  def test_work_dprogram_aggregates
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = <<EOD
ruby*:::function-entry
{ 
  @a[execname, copyinstr(arg1), copyinstr(arg2)] = count(); 
  printf("foo");
}

profile-10
{
  printa(@a)
}
EOD

    prog = t.compile progtext
    prog.execute
    
    c = DtraceConsumer.new(t)

    begin
      i = 0
      c.consume do |e|
        assert e
        case e.class.to_s
        when "DtraceProbeData"
          assert e.probedesc
          e.each_record do |r|
            assert r.value
          end
        when "DtraceRecord"
          assert e.value
        when "DtraceAggregate"
          assert e.value
          assert e.tuple
          assert_equal 3, e.tuple.length
        end
          
        i = i + 1
        if i > 100
          break
        end
      end
    rescue Interrupt
      puts "interrupted"
    end
   
  end

  def test_work_dprogram_once
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")
    
    progtext = "ruby*:::function-entry{ @a[execname, copyinstr(arg1), copyinstr(arg2)] = count(); } END { printa(@a); }"

    prog = t.compile progtext
    prog.execute

    t.go

    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end
    
    c = DtraceConsumer.new(t)
    c.consume_once do |e|
      if e && e.class == DtraceAggregate
        assert e.value
        assert e.tuple
        assert_equal 3, e.tuple.length
      end
    end
  end
  
end
