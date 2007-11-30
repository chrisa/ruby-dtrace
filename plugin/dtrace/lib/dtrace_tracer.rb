require 'dtrace'

class Dtracer
  
  def start_dtrace(pid)
    @d = Dtrace.new
    @d.setopt("aggsize", "4m")
    @d.setopt("bufsize", "4m")
    progtext = 'ruby$1:::function-entry{ @[strjoin(strjoin(copyinstr(arg0),"."),copyinstr(arg1))] = count(); }'
    begin
      prog = @d.compile(progtext, pid.to_s)
      prog.execute
      @d.go
    rescue DtraceException => e
      puts "start: #{e.message}"
    end
  end
  
  def end_dtrace(pid)
    begin
      @d.stop
      @d.aggregate_snap
      
      dtrace_report = Hash.new
      @d.each_aggregate do |agg|
        dtrace_report[agg[1].data] = agg[2].data
      end
    rescue DtraceException => e
      puts "end: #{e.message}"
    end

    return dtrace_report
  end
end
