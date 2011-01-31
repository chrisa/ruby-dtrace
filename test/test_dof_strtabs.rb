#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'

class TestDofStrtabs < Test::Unit::TestCase
  include Dtrace::Dof::Constants
  
  def test_strtab_stridxs
    sec = Dtrace::Dof::Section::Strtab.new(1)
    assert sec
    
    assert_equal 1, sec.add('foo')
    assert_equal 5, sec.add('bar')
    assert_equal 9, sec.add('baz')
  end

  def test_strtab_dof
    f = Dtrace::Dof::File.new
    f.allocate(4096)

    strtab = Dtrace::Dof::Section::Strtab.new(0)
    f.sections << strtab

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {
                :name     => strtab.add('test'),
                :func     => strtab.add('main'),
                :noffs    => 1,
                :enoffidx => 0,
                :argidx   => 0,
                :nenoffs  => 0,
                :offidx   => 0,
                :addr     => 0,
                :nargc    => 0,
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
    s.data = [ 36 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :prenoffs => 4,
      :name => strtab.add('teststrtabs'),
      :provattr => { 
        :name  => DTRACE_STABILITY_EVOLVING,
        :data  => DTRACE_STABILITY_EVOLVING,
        :class => DTRACE_STABILITY_EVOLVING 
      },
      :modattr  => { 
        :name => DTRACE_STABILITY_PRIVATE,
        :data => DTRACE_STABILITY_PRIVATE,
        :class => DTRACE_STABILITY_EVOLVING 
      },
      :funcattr => { 
        :name => DTRACE_STABILITY_PRIVATE,
        :data => DTRACE_STABILITY_PRIVATE,
        :class => DTRACE_STABILITY_EVOLVING
      },
      :nameattr => { 
        :name => DTRACE_STABILITY_EVOLVING,
        :data => DTRACE_STABILITY_EVOLVING,
        :class => DTRACE_STABILITY_EVOLVING
      },
      :argsattr => {
        :name => DTRACE_STABILITY_EVOLVING,
        :data => DTRACE_STABILITY_EVOLVING,
        :class => DTRACE_STABILITY_EVOLVING
      },
    }
    f.sections << s

    f.generate
    Dtrace::Dof.loaddof(f, 'testmodule')
  end

end
