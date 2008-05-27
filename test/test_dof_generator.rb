#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'
require 'pp'

$dof_dir = File.dirname(__FILE__)

# Tests for the Dtrace DOF generator

class TestDofGenerator < Test::Unit::TestCase
  include Dtrace::Dof::Constants

  def test_generate_section_comments
    s = Dtrace::Dof::Section.new(DOF_SECT_COMMENTS, 1)
    s.data = "Ruby-Dtrace D 0.12"
    dof = s.generate
    assert dof
  end

  def test_generate_section_utsname
    s = Dtrace::Dof::Section.new(DOF_SECT_UTSNAME, 2)
    dof = s.generate
    assert dof
  end
    
  def test_generate_section_probes
    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 3)
    s.data = [
              {:enoffidx=>14,
                :argidx=>16,
                :nenoffs=>1,
                :offidx=>14,
                :name=>1,
                :addr=>0x8082a78,
                :nargc=>1,
                :func=>5,
                :xargc=>1,
                :nargv=>3,
                :noffs=>1,
                :xargv=>3},
              {:enoffidx=>15,
                :argidx=>17,
                :nenoffs=>1,
                :offidx=>15,
                :name=>4,
                :addr=>0x807429c,
                :nargc=>3,
                :func=>9,
                :xargc=>3,
                :nargv=>6,
                :noffs=>1,
                :xargv=>7},
             ]
    
    dof = s.generate
    assert dof
  end

  def test_generate_section_strtab
    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 1)
    s.data = ['foo', 'bar', 'baz']
    dof = s.generate
    assert dof
  end

  def test_generate_section_prargs
    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 1)
    s.data = [ 1, 2 ]
    dof = s.generate
    assert dof
  end

  def test_generate_section_proffs
    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 1)
    s.data = [ 3, 4 ]
    dof = s.generate
    assert dof
  end

  def test_generate_section_proffs
    s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 1)
    s.data = [ 5, 6 ]
    dof = s.generate
    assert dof
  end

  def test_generate_section_provider
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 1)
    data = {
      :strtab => 1,
      :probes => 2,
      :prargs => 3,
      :proffs => 4,
      :prenoffs => 5,
      :name => 1,
      :provattr => { :name => 1, :data => 1, :class => 1 },
      :modattr  => { :name => 1, :data => 1, :class => 1 },
      :funcattr => { :name => 1, :data => 1, :class => 1 },
      :nameattr => { :name => 1, :data => 1, :class => 1 },
      :argsattr => { :name => 1, :data => 1, :class => 1 }
    }
    s.data = data
    dof = s.generate
    assert dof
  end

  def test_dof_generate_section_reltab
    s = Dtrace::Dof::Section.new(DOF_SECT_RELTAB, 5)
    data = [
            { :name   => 20, # main
              :type   => 1,  # setx?
              :offset => 0,
              :data   => 0,
            }
           ]
    s.data = data
    dof = s.generate
    assert dof
  end

  def test_dof_generate_section_urelhdr
    s = Dtrace::Dof::Section.new(DOF_SECT_URELHDR, 6)
    data = {
      :strtab => 0,
      :relsec => 5,
      :tgtsec => 1,
    }
    s.data = data
    dof = s.generate
    assert dof
  end

  def test_const
    assert Dtrace::Dof::Constants::DOF_SECT_UTSNAME
    assert DOF_SECT_UTSNAME
  end
end
