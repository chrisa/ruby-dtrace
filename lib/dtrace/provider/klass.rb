#
# Ruby-Dtrace
# (c) 2009 Chris Andrews <chris@nodnol.org>
#

class Dtrace
  class Provider

    # A dynamically-created DTrace provider class. 
    #
    class Klass
      
      def initialize(dof, probes)
        # must stash a reference to the DOF in the provider:
        # on OSX at least, freeing the generated DOF removes
        # the probes from the kernel. 
        @dof = dof
        @probes = probes
      end
      
      def method_missing(probe, *args, &block)
        if @probes[probe].nil?
          raise Dtrace::Exception.new("no such probe in #{self.to_s}: #{probe.to_s}")
        else 
          if @probes[probe].is_enabled?
            block.call @probes[probe]
          end
        end
      end

    end
  end
end
