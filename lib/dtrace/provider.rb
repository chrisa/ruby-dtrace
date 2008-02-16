#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace/probe'
require 'dtrace/provider/solaris'
require 'dtrace/provider/osx'
require 'pathname'

DTRACE = '/usr/sbin/dtrace'

class Dtrace
  class Provider

    def self.create(name)
      if RUBY_PLATFORM =~ /darwin/
        provider = Dtrace::Provider::OSX.new(name)
      else
        provider = Dtrace::Provider::Solaris.new(name)
      end
      yield provider
      provider.enable
    end
    
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

    def enable
      Tempfile.open("dtrace_probe_#{@name}") do |f|
        p = Pathname.new(f.path)
        @tempdir = "#{p.dirname}/#{@name}" 
        begin
          Dir.mkdir @tempdir
        rescue Errno::EEXIST
          nil
        end

        definition
        header
        source
        ruby_object
        dtrace_object
        link
        load
      end
    end

    # compose provider definition .d file
    def definition
      stability = <<EOS
#pragma D attributes Evolving/Evolving/Common provider #{@name} provider
#pragma D attributes Private/Private/Common provider #{@name} module
#pragma D attributes Private/Private/Common provider #{@name} function
#pragma D attributes Evolving/Evolving/Common provider #{@name} name
#pragma D attributes Evolving/Evolving/Common provider #{@name} args
EOS
      File.open("#{@tempdir}/probes.d", 'w') do |io|
        io << "provider #{@name} {\n"
        @probes.each_pair do |name, types|
          probename = name.to_s.gsub(/_/, '__')
          typesdesc = types.join(', ')
          probedesc = "  probe #{probename}(#{typesdesc});\n"
          io << probedesc
        end
        io << "\n};\n\n#{stability}"
      end
    end

    def header
      Kernel.system("#{DTRACE} -h -s #{@tempdir}/probes.d -o #{@tempdir}/probes.h")
    end

    # Generate the C source for the provider class
    def source
      rb2c = { 'char *' => 'STR2CSTR', 'int' => 'FIX2INT' }
      
      File.open("#{@tempdir}/probes.c", 'w') do |io|
        io.puts '#include "ruby.h"'
        io.puts "#include \"#{@tempdir}/probes.h\""

        @probes.each_pair do |name, types|
          defn_args = []
          call_args = []
          types.each_with_index { |type, i| defn_args << "#{type} arg#{i}" }
          types.each_with_index { |type, i| call_args << "#{rb2c[type]}(rb_ary_entry(args, #{i}))" }
          
          io.puts <<EOC
static VALUE #{name}(VALUE self) {
  if (#{@name.upcase}_#{name.to_s.upcase}_ENABLED()) {
    VALUE args = rb_yield(self);
    #{@name.upcase}_#{name.to_s.upcase}(#{call_args.join(', ')});
  }
  return Qnil;
}
EOC
        end
        io.puts <<EOC
static VALUE fire(VALUE self, VALUE args) {
  return args;
}

void Init_#{@name}() {
  fprintf(stderr, "in Init_#{@name}\\n");
  VALUE c = rb_cObject;
  rb_define_method(c, "fire", (VALUE(*)(ANYARGS))fire, -2);
EOC
        
        @probes.each_pair do |name, types|
          io.puts "  rb_define_singleton_method(c, \"#{name}\", (VALUE(*)(ANYARGS))#{name}, 0);"
        end
        
        io.puts '}'
      end
    end
    
    def load
      lib = "#{@tempdir}/#{@name}"
      c = Class.new
      c.module_eval do 
        require lib
      end
      eval "Dtrace::Probe::#{@class} = c"
    end

    def hdrdir
      %w(srcdir archdir).map { |name|
        dir = Config::CONFIG[name]
      }.find { |dir|
        dir and File.exist? File.join(dir, "/ruby.h")
      } or abort "ERROR: Can't find header dir for ruby. Exiting..."
    end

  end
end
