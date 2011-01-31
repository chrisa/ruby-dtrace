#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'

class TestDtraceProbe < Test::Unit::TestCase
  include Dtrace::Dof::Constants
  
  def test_probe
    p = Dtrace::Probe.new(0)
  end

  def test_fire_probe
    p = Dtrace::Probe.new(0)
    p.fire
  end

  def test_is_probe_not_enabled
    p = Dtrace::Probe.new(0)
    assert !p.is_enabled?
  end

  def test_fire_probe_no_args
    probe = Dtrace::Probe.new(0)
    addr = probe.addr

    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['args', 'main', 'testprobe']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :noffs    => 1,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 1,
                :offidx   => 0,
                :addr     => addr,
                :nargc    => 0,
                :func     => 6,
                :xargc    => 0,
                :nargv    => 0,
                :xargv    => 0
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ probe.probe_offset(f.addr, 0) ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ probe.is_enabled_offset(f.addr) ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab   => 0,
      :probes   => 1,
      :prargs   => 2,
      :proffs   => 3,
      :prenoffs => 4,
      :name     => 11,
      :provattr => { :name => 5, :data => 5, :class => 5 },
      :modattr  => { :name => 1, :data => 1, :class => 5 },
      :funcattr => { :name => 1, :data => 1, :class => 5 },
      :nameattr => { :name => 5, :data => 5, :class => 5 },
      :argsattr => { :name => 5, :data => 5, :class => 5 }
    }
    f.sections << s

    f.generate
    Dtrace::Dof.loaddof(f, 'testmodule')
  
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    matches = 0
    t.each_probe("testprobe#{$$}:testmodule:main:args") do |p|
      matches += 1
    end
    assert_equal 1, matches

    progtext = <<EOD
test*:testmodule:main:args
{
  trace("fired!");
}
EOD

    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    probe.fire

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'fired!', data[0].data[0].value
  end

  def test_fire_probe_two_int_args
    probe = Dtrace::Probe.new(2)
    addr = probe.addr

    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'tes2', 'int', 'int', 'int', 'int']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :nargv    => 16,
                :noffs    => 1,
                :xargv    => 24,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 1,
                :offidx   => 0,
                :addr     => addr,
                :nargc    => 2,
                :func     => 6,
                :xargc    => 2
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0, 1 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ probe.probe_offset(f.addr, 2) ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ probe.is_enabled_offset(f.addr) ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab   => 0,
      :probes   => 1,
      :prargs   => 2,
      :proffs   => 3,
      :prenoffs => 4,
      :name     => 11,
      :provattr => { :name => 5, :data => 5, :class => 5 },
      :modattr  => { :name => 1, :data => 1, :class => 5 },
      :funcattr => { :name => 1, :data => 1, :class => 5 },
      :nameattr => { :name => 5, :data => 5, :class => 5 },
      :argsattr => { :name => 5, :data => 5, :class => 5 }
    }
    f.sections << s

    f.generate
    Dtrace::Dof.loaddof(f, 'testmodule')

    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
tes2*:testmodule:main:test
{
  trace(arg0);
  trace(arg1);
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    probe.fire(41, 42)

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 41, data[0].data[0].value
    assert_equal 42, data[0].data[1].value
  end

  def test_fire_probe_two_charstar_args
    probe = Dtrace::Probe.new(2)
    addr = probe.addr

    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'tes3', 'char *', 'char *', 'char *', 'char *']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :nargv    => 16,
                :noffs    => 1,
                :xargv    => 30,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 1,
                :offidx   => 0,
                :addr     => addr,
                :nargc    => 2,
                :func     => 6,
                :xargc    => 2
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0, 1 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ probe.probe_offset(f.addr, 2) ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ probe.is_enabled_offset(f.addr) ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab   => 0,
      :probes   => 1,
      :prargs   => 2,
      :proffs   => 3,
      :prenoffs => 4,
      :name     => 11,
      :provattr => { :name => 5, :data => 5, :class => 5 },
      :modattr  => { :name => 1, :data => 1, :class => 5 },
      :funcattr => { :name => 1, :data => 1, :class => 5 },
      :nameattr => { :name => 5, :data => 5, :class => 5 },
      :argsattr => { :name => 5, :data => 5, :class => 5 }
    }
    f.sections << s

    f.generate
    Dtrace::Dof.loaddof(f, 'testmodule')

    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
tes3*:testmodule:main:test
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = Dtrace::Consumer.new(t)

    probe.fire('foo', 'bar')

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'foo', data[0].data[0].value
    assert_equal 'bar', data[0].data[1].value
  end

  def test_probe_is_enabled
    probe = Dtrace::Probe.new(0)
    addr = probe.addr

    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'tes4']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :noffs    => 1,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 1,
                :offidx   => 0,
                :addr     => addr,
                :nargc    => 0,
                :func     => 6,
                :xargc    => 0,
                :nargv    => 0,
                :xargv    => 0
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ probe.probe_offset(f.addr, 0) ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ probe.is_enabled_offset(f.addr) ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab   => 0,
      :probes   => 1,
      :prargs   => 2,
      :proffs   => 3,
      :prenoffs => 4,
      :name     => 11,
      :provattr => { :name => 5, :data => 5, :class => 5 },
      :modattr  => { :name => 1, :data => 1, :class => 5 },
      :funcattr => { :name => 1, :data => 1, :class => 5 },
      :nameattr => { :name => 5, :data => 5, :class => 5 },
      :argsattr => { :name => 5, :data => 5, :class => 5 }
    }
    f.sections << s

    f.generate
    Dtrace::Dof.loaddof(f, 'testmodule')

    assert !probe.is_enabled?

    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
tes4*:testmodule:main:test
{
  trace("fired!");
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    
    assert probe.is_enabled?
    
    probe.fire

    c = Dtrace::Consumer.new(t)
    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'fired!', data[0].data[0].value
  end

end
