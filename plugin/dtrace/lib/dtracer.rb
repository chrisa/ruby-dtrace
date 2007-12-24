require 'dtrace'

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
        printf("report:syscalls");
        printa(@syscalls);
        printf("report:rbclasses");
        printa(@rbclasses);
        printf("report:rbmethods");
        printa(@rbmethods);
        printf("report:queries");
        printa(@queries);
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
    return {} unless @d

    current_report = 'none'
    begin
      dtrace_report = Hash.new
      c = DtraceConsumer.new(@d)
      c.consume_once do |e|
        if e.respond_to? :tuple
          dtrace_report[current_report][e.tuple.first] = e.value
        elsif e.respond_to? :value
          if e.value =~ /report:(.*)/
            current_report = Regexp.last_match(1)
            unless dtrace_report[current_report]
              dtrace_report[current_report] = Hash.new
            end
          end
        end
      end
    rescue DtraceException => e
      puts "end: #{e.message}"
    end

    return dtrace_report
  end
end
