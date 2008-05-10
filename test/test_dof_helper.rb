#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'
require 'pp'

$dof_dir = File.dirname(__FILE__)

class TestDofHelper < Test::Unit::TestCase
  include Dtrace::Dof::Constants
  
  def test_sun_dof
    dof = File.read("#{$dof_dir}/dof")
    Dtrace.loaddof(dof)

    d = Dtrace::Dof::Parser.parse(dof)
    pp d

    t = Dtrace.new

    matches = 0
    t.each_probe do |p|
      if p.to_s == "test#{$$}:testmodule:main:test"
        matches += 1
      end
    end
    assert_equal 1, matches
  end
  
  def test_file
    f = Dtrace::Dof::File.new

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'char *', 'char *', 'main', 'test']
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
    s.data = [
              {:nargv=>6,
               :noffs=>1,
               :xargv=>13,
               :enoffidx=>0,
               :argidx=>0,
               :name=>1,
               :nenoffs=>0,
               :offidx=>0,
               :addr=>0,
               :nargc=>1,
               :func=>20,
               :xargc=>1}
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ 36 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 4)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :name => 25,
      :provattr => { :name => 1, :data => 1, :class => 1 },
      :modattr  => { :name => 1, :data => 1, :class => 1 },
      :funcattr => { :name => 1, :data => 1, :class => 1 },
      :nameattr => { :name => 1, :data => 1, :class => 1 },
      :argsattr => { :name => 1, :data => 1, :class => 1 }
    }
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_UTSNAME, 5)
    f.sections << s

    dof = f.generate
    assert dof

    d = Dtrace::Dof::Parser.parse(dof)
    pp d

    Dtrace.loaddof(dof)
    t.each_probe do |p|
      puts p
    end

  end

end
