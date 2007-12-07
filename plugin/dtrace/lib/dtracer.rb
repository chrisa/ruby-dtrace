require 'dtrace'

class Dtracer
  
  def start_dtrace(pid)
    progtext = 'ruby$1:::function-entry{ @a[strjoin(strjoin(copyinstr(arg0),"."),copyinstr(arg1))] = count(); } END { printa(@a); }'

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

    begin
      dtrace_report = Hash.new
      c = DtraceConsumer.new(@d)
      c.consume_once do |e|
        if e.respond_to? :tuple
          dtrace_report[e.tuple.first] = e.value
        end
      end
    rescue DtraceException => e
      puts "end: #{e.message}"
    end

    return dtrace_report
  end
end
