require 'test_helper'

class TestRubyprobe < DTraceTest

  def test_rubyprobe
    progtext = <<EOD
ruby*:::ruby-probe
{
  trace(copyinstr(arg0));
  trace(copyinstr(arg1));
}
EOD

    begin
      prog = @dtp.compile progtext
      prog.execute
      @dtp.go
    rescue DTrace::Exception
      nil
    end

    if prog

      c = DTrace::Consumer.new(@dtp)

      # Leopard's ruby-probe is DTracer, Solaris's is Tracer.
      begin
        trace_module = DTracer
      rescue NameError
        begin
          trace_module = Tracer
        end
      end

      (0..9).each do |i|
        trace_module.fire("foo", i.to_s)
      end

      data = []
      c.consume_once do |d|
        data << d
      end

      (0..9).each do |i|
        d = data.shift
        assert_equal("foo", d.data[0].value)
        assert_equal(i.to_s, d.data[1].value)
      end
    end
  end

end
