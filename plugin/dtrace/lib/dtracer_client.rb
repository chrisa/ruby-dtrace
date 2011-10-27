require 'drb'

class DtracerClient
  attr_writer :logger
  attr_reader :script

  def initialize
    DRb.start_service
    @tracer = DRbObject.new(nil, 'druby://localhost:2999')
  end

  def script=(script)
    @script = script
    scriptdir = File.expand_path(File.dirname(__FILE__) + "/../scripts")
    @tracer.dprogram = IO.read("#{scriptdir}/#{script}")
  end

  def start_dtrace(pid)
    @tracer.start_dtrace(pid)
  end

  def end_dtrace
    @tracer.end_dtrace
  end

end
