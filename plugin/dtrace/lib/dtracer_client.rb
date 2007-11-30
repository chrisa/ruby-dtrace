require 'drb'

class DtracerClient

  def initialize
    DRb.start_service
    @tracer = DRbObject.new(nil, 'druby://localhost:2999')  
  end

  def start_dtrace(pid)
    @tracer.start_dtrace(pid)
  end
  
  def end_dtrace
    @tracer.end_dtrace
  end
  
end
