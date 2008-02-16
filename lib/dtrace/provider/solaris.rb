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
        run "#{Config::CONFIG['CC']} -I#{hdrdir} -o #{@tempdir}/#{@name}.o -c #{@tempdir}/probes.c"
      end

      # build the dtrace.o (dtrace -G)
      def dtrace_object
        run "/usr/sbin/dtrace -G -s #{@tempdir}/probes.d -o #{@tempdir}/probes.o #{@tempdir}/#{@name}.o"
      end

      # build the .so
      def link
        run "#{Config::CONFIG['CC']} -shared -o #{@tempdir}/#{@name}.so #{@tempdir}/#{@name}.o #{@tempdir}/probes.o"
      end

    end
  end
end
