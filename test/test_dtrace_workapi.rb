require 'dtrace'
require 'test/unit'

class TestDtrace < Test::Unit::TestCase
  def test_work_dprogram_run
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = "syscall:::entry { trace(probefunc); trace(execname); }"
    
    prog = t.compile progtext
    prog.execute
    t.go

    c = DtraceConsumer.new(t)
    assert c

    i = 0
    c.consume do |d|
      i = i + 1
      if i > 10
        break
      end
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
    t.go
    
    c = DtraceConsumer.new(t)

    i = 0
    c.consume do |d|
      assert d
      i = i + 1
      if i >= 10
        break
      end
    end
    
  end

  def test_work_dprogram_aggregates_once
    t = Dtrace.new 
    t.setopt("bufsize", "4m")
    t.setopt("aggsize", "4m")

    progtext = <<EOD
ruby*:::function-entry
{ 
  @a[execname, copyinstr(arg1), copyinstr(arg2)] = count(); 
}

END
{
  printa(@a)
}
EOD

    prog = t.compile progtext
    prog.execute

    t.go
    
    foo = 0
    (1..1000).each do |i|
      foo = foo + i
    end
    
    c = DtraceConsumer.new(t)
    
    c.consume_once do |d|
      assert d
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
    c.consume_once do |d|
      assert d
    end
  end

  def test_work_stacks
    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = "syscall:::entry { trace(execname); stack(); }"
    prog = t.compile progtext
    prog.execute
    t.go

    c = DtraceConsumer.new(t)
    i = 0
    c.consume do |d|
      assert d
      i = i + 1
      if i > 10
        break
      end
    end

    t = Dtrace.new 
    t.setopt("bufsize", "8m")
    t.setopt("aggsize", "4m")
    t.setopt("stackframes", "5")
    t.setopt("strsize", "131072")

    progtext = "syscall:::entry { trace(execname); ustack(); }"
    prog = t.compile progtext
    prog.execute
    t.go

    c = DtraceConsumer.new(t)
    i = 0
    c.consume do |d|
      assert d
      i = i + 1
      if i > 10
        break
      end
    end
  end
  
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
