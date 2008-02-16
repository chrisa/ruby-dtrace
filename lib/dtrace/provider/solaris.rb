#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'rbconfig'

class Dtrace
  class Provider
    class Solaris < Provider

      # build the .o 
      def ruby_object
        cmd = "#{Config::CONFIG['CC']} -I#{hdrdir} -o #{@tempdir}/#{@name}.o -c #{@tempdir}/probes.c"
        Kernel.system cmd
      end

      # build the dtrace.o (dtrace -G)
      def dtrace_object
        cmd = "/usr/sbin/dtrace -G -s #{@tempdir}/probes.d -o #{@tempdir}/probes.o #{@tempdir}/#{@name}.o"
        Kernel.system cmd
      end

      # build the .so
      def link
        cmd = "#{Config::CONFIG['CC']} -shared -o #{@tempdir}/#{@name}.so #{@tempdir}/#{@name}.o #{@tempdir}/probes.o"
        Kernel.system cmd
      end

    end
  end
end
