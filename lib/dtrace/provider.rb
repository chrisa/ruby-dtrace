#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#
require 'inline/dtrace_probes'

DTRACE = '/usr/sbin/dtrace'

class Dtrace
  class Provider

    # Pinched from ActiveSupport's Inflector
    def camelize(lower_case_and_underscored_word)
      lower_case_and_underscored_word.to_s.gsub(/\/(.?)/) { "::" + $1.upcase }.gsub(/(^|_)(.)/) { $2.upcase }
    end
    
    def initialize(name)
      @name   = name.to_s
      @class  = camelize(name)
      @probes = {}
    end

    def probe(name, *types)
      typemap = { :string => 'char *', :integer => 'int' }
      @probes[name] = types.map {|t| typemap[t]}
    end

    def build
      # compose provider definition .d file
      stability = <<EOS
#pragma D attributes Evolving/Evolving/Common provider #{@name} provider
#pragma D attributes Private/Private/Common provider #{@name} module
#pragma D attributes Private/Private/Common provider #{@name} function
#pragma D attributes Evolving/Evolving/Common provider #{@name} name
#pragma D attributes Evolving/Evolving/Common provider #{@name} args
EOS
      
      providerdesc = "provider #{@name} {\n"
      @probes.each_pair do |name, types|
        probename = name.to_s.gsub(/_/, '__')
        typesdesc = types.join(', ')
        probedesc = "  probe #{probename}(#{typesdesc});\n"
        providerdesc << probedesc
      end
      providerdesc << "\n};\n\n#{stability}"
      
      # Generate the C source for the provider class
      fns = []

      rb2c = { 'char *' => 'STR2CSTR', 'int' => 'FIX2INT' }

      @probes.each_pair do |name, types|
        defn_args = []
        call_args = []
        types.each_with_index { |type, i| defn_args << "#{type} arg#{i}" }
        types.each_with_index { |type, i| call_args << "#{rb2c[type]}(rb_ary_entry(args, #{i}))" }

        cstr = <<EOC
void #{name}(void) {
  if (#{@name.upcase}_#{name.to_s.upcase}_ENABLED()) {
    VALUE args = rb_yield(self);
    #{@name.upcase}_#{name.to_s.upcase}(#{call_args.join(', ')});
  }
}
EOC
        fns << cstr
      end

      # write out provider description, run dtrace -h
      Tempfile.open('header') do |h|
        Tempfile.open('provider') do |d|
          d.puts providerdesc
          d.flush
          Kernel.system("#{DTRACE} -h -s #{d.path} -o #{h.path}")
        end
        
        # Create the provider class
        c = Class.new
        c.module_eval do
          inline('DtraceProbes') do |builder|
            builder.set_module_name "rubydtrace"
            builder.include "\"#{h.path}\""
            builder.c_raw <<EOC
static VALUE fire(VALUE self, VALUE args) {
  return args;
}
EOC
            fns.each do |cstr|
              builder.c cstr
            end
          end
        end
        eval "Dtrace::Probe::#{@class} = c"
      end
      
    end
  end
end
