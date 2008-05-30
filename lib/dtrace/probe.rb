#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'

class Dtrace
  # DTrace::Probe - Using dynamically created USDT probes in Ruby
  # programs:
  #
  # Having created the following probes with Dtrace::Provider:
  #
  #   74777 action_controller12297 action_controller.so process_finish process-finish
  #   74778 action_controller12297 action_controller.so process_start process-start
  # 
  # you can fire them with the following Ruby statements:
  #
  #   Dtrace::Probe::ActionController.process_start do |p|
  #     p.fire(request.url)
  #   end
  #
  # Note that the generated class corresponding to the provider is
  # simply the provider class, camelized. 
  #
  # The generated method corresponding to the probe name (with -
  # replaced by _) yields a probe object, on which you can call fire(),
  # passing arguments of the appropriate types -- you are responsible
  # for any type conversions necessary. 
  #
  # fire() takes as many arguments as you defined for the probe: if
  # you have generated a list of arguments to pass to fire(), use the
  # splat operator to expand the list:
  # 
  #   Dtrace::Probe::MyProvider.my_probe do |p|
  #     args_list = [ some operation to get a list ]
  #     p.fire(*args_list)
  #   end
  # 
  # This yield/fire() syntax exposes the is-enabled feature of the
  # generated USDT probes: if the probe is not enabled, then the yield
  # does not happen: this allows you to put relatively expensive work
  # in the block, and know it is only called if the probe is enabled.
  # This way, the probe-disabled overhead of these providers is
  # reduced to a single method call, to a C-implemented method which
  # simply wraps the DTrace IS_ENABLED() macro for the probe.
  #
  class Probe
    def initialize(argc)
      @stub = DtraceStub.new(argc)
    end

    def fire(*args)
      @stub.call(*args)
    end

    def addr
      @stub.addr
    end
  end
end

