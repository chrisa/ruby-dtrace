#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'

class TestDofProviders < Test::Unit::TestCase
  include Dtrace::Dof::Constants
  
  def test_probe_no_args
    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'test1dof']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :noffs    => 1,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 0,
                :offidx   => 0,
                :addr     => 0,
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
    s.data = [ 36 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ 0 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :prenoffs => 4,
      :name   => 11,
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
    matches = 0
    t.each_probe("test1dof#{$$}:testmodule:main:test") do |p|
      matches += 1
    end
    assert_equal 1, matches

  end

  def test_probe_with_char_arg
    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'char *', 'char *', 'main', 'test2dof']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :nargv    => 6,
                :noffs    => 1,
                :xargv    => 13,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 0,
                :offidx   => 0,
                :addr     => 0,
                :nargc    => 1,
                :func     => 20,
                :xargc    => 1
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ 36 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ 0 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :prenoffs => 4,
      :name   => 25,
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
    matches = 0
    t.each_probe("test2dof#{$$}:testmodule:main:test") do |p|
      matches += 1
    end

    assert_equal 1, matches
  end

  def test_probe_with_int_arg
    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'int', 'int', 'main', 'test3dof']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :nargv    => 6,
                :noffs    => 1,
                :xargv    => 10,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 0,
                :offidx   => 0,
                :addr     => 0,
                :nargc    => 1,
                :func     => 14,
                :xargc    => 1
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ 36 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ 36 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :prenoffs => 4,
      :name   => 19,
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
    matches = 0
    t.each_probe("test3dof#{$$}:testmodule:main:test") do |p|
      matches += 1
    end
    assert_equal 1, matches

  end

  def test_probe_is_enabled
    f = Dtrace::Dof::File.new
    f.allocate(4096)

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'test4dof']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :noffs    => 1,
                :enoffidx => 0,
                :argidx   => 0,
                :name     => 1,
                :nenoffs  => 0,
                :offidx   => 0,
                :addr     => 0,
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
    s.data = [ 36 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
    s.data = [ 44 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :name => 11,
      :strtab   => 0,
      :probes   => 1,
      :prargs   => 2,
      :proffs   => 3,
      :prenoffs => 4,
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
    matches = 0
    t.each_probe("test4dof#{$$}:testmodule:main:test") do |p|
      matches += 1
    end
    assert_equal 1, matches

  end

end

