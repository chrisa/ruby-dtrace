require 'dtrace'
require 'pp'

class Dtracer
  
  def start_dtrace(pid)
    progtext = <<EOD
self string uri;

pid$1::mysql_real_query:entry
{
        @queries[copyinstr(arg1)] = count();
}

ruby$1:::function-entry
{
        @rbclasses[this->class = copyinstr(arg0)] = count();
        this->sep = strjoin(this->class, "#");
        @rbmethods[strjoin(this->sep, copyinstr(arg1))] = count();
}

syscall:::entry
{
        @syscalls[probefunc] = count();
}

END
{
        printf("MySQL Queries");
        printa(@queries);
        printf("System Calls");
        printa(@syscalls);
        printf("Ruby Classes");
        printa(@rbclasses);
        printf("Ruby Methods");
        printa(@rbmethods);
}

EOD

    begin
      @d = Dtrace.new
      @d.setopt("aggsize", "4m")
      @d.setopt("bufsize", "4m")
    rescue DtraceException => e
      puts "start setup: #{e.message}"
      return
    end

    begin
      prog = @d.compile(progtext, pid.to_s)
      prog.execute
      @d.go
    rescue DtraceException => e
      puts "start: #{e.message}"
    end

  end
  
  def end_dtrace
    return [] unless @d

    dtrace_data = nil
    current_report = 'none'
    begin
      c = DtraceConsumer.new(@d)
      c.consume_once do |d|
        dtrace_data = d
      end
    rescue DtraceException => e
      puts "end: #{e.message}"
    end

    return dtrace_data.data
  end
end
