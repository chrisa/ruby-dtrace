require 'dtrace'

class Dtracer
  attr_writer :logger, :dprogram
  attr_reader :script

  def script=(script)
    @script = script
    scriptdir = File.expand_path(File.dirname(__FILE__) + "/../scripts")
    @dprogram = IO.read("#{scriptdir}/#{script}")
  end

  def start_dtrace(pid)
    begin
      @d = Dtrace.new
      @d.setopt("aggsize", "4m")
      @d.setopt("bufsize", "4m")
    rescue DtraceException => e
      @logger.warn("DTrace start setup: #{e.message}")
      return
    end

    begin
      prog = @d.compile(@dprogram, pid.to_s)
      prog.execute
      @d.go
    rescue DtraceException => e
      @logger.warn("DTrace start compile: #{e.message}")
    end
  end
  
  def end_dtrace
    # Check presence of handle and correct status.
    return [] unless @d && @d.status == Dtrace::STATUS_OKAY

    dtrace_data = nil
    begin
      c = DtraceConsumer.new(@d)
      c.consume_once do |d|
        dtrace_data = d
      end
    rescue DtraceException => e
      @logger.warn("DTrace end: #{e.message}")
    end
    
    if dtrace_data
      return dtrace_data.data
    else
      return []
    end
  end
end
