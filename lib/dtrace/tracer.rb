#
# Ruby-DTrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# Leopard's ruby-probe is DTracer, Solaris's is Tracer.

class DTrace
  class Tracer
    
    class NullTracer
      def self.fire(arg0, arg1)
        puts "NullTracer: #{arg0} #{arg1}"
      end
    end

    @@tracer = nil
    def self.fire(*args)
      if @@tracer == nil
        begin
          # Avoid getting ourselves here:
          @@tracer = Module.const_get('Tracer')
        rescue NameError
          begin
            @@tracer = DTracer
          rescue NameError
            @@tracer = DTrace::Tracer::NullTracer
          end
        end
      end
      @@tracer.fire(*args)
    end
          
  end
end
