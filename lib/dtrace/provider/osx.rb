#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class Dtrace
  class Provider
    class OSX < Provider
      
      # build the .bundle
      def ruby_object
        cmd = "#{Config::CONFIG['LDSHARED']} -I #{hdrdir} -o #{@tempdir}/#{@name}.bundle #{@tempdir}/probes.c"
        Kernel.system cmd
      end

      def dtrace_object
        # no-op on OSX
      end

      def link
        # no-op on OSX
      end
      
    end
  end
end
