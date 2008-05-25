#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'test/unit'
require 'pp'

class TestDofHelper < Test::Unit::TestCase
  include Dtrace::Dof::Constants
  
  def test_stub
    s = DtraceStub.new
  end

  def test_call_stub
    s = DtraceStub.new
    s.call
  end

  def test_fire_probe_no_args
    stub = DtraceStub.new
    addr = stub.addr

    f = Dtrace::Dof::File.new

    s = Dtrace::Dof::Section.new(DOF_SECT_STRTAB, 0)
    s.data = ['test', 'main', 'test']
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
                :addr     => addr,
                :nargc    => 0,
                :func     => 6,
                :xargc    => 0
              },
             ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
    s.data = [ 0 ]
    f.sections << s

    s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
    s.data = [ 30 ]
    f.sections << s
    
    s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 4)
    s.data = {
      :strtab => 0,
      :probes => 1,
      :prargs => 2,
      :proffs => 3,
      :name   => 11,
      :provattr => { :name => 5, :data => 5, :class => 5 },
      :modattr  => { :name => 1, :data => 1, :class => 5 },
      :funcattr => { :name => 1, :data => 1, :class => 5 },
      :nameattr => { :name => 5, :data => 5, :class => 5 },
      :argsattr => { :name => 5, :data => 5, :class => 5 }
    }
    f.sections << s

    dof = f.generate
    Dtrace.loaddof(dof)
  
    t = Dtrace.new 
    t.setopt("bufsize", "4m")

    progtext = <<EOD
test*:testmodule:main:test
{
  trace("fired!");
}
EOD
    
    prog = t.compile progtext
    prog.execute
    t.go
    c = DtraceConsumer.new(t)

    stub.call

    data = []
    c.consume_once do |d|
      data << d
    end

    assert_equal 1, data.length
    assert_equal 'fired!', data[0].data[0].value
  end
end
