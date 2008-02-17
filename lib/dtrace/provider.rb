#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

require 'dtrace/probe'
require 'dtrace/provider/solaris'
require 'dtrace/provider/osx'
require 'pathname'
require 'tempfile'

DTRACE = '/usr/sbin/dtrace'

class Dtrace

  # A DTrace provider. Allows creation of USDT probes on a running
  # Ruby program, by dynamically creating an extension module
  # implementing the probes, and compiling and loading it.
  #
  # This requires the DTrace and Ruby toolchains to be available:
  # dtrace(1M), and the compiler and linker used to build Ruby. The
  # process is similar to RubyInline, but the actual RubyInline
  # library is not required (the build process for DTrace USDT probes
  # is sufficiently differnent to a standard Ruby extension that it's
  # not worth using it).
  #
  # Both Solaris and OSX 10.5 are supported. Other DTrace-supporting
  # platforms can be added by creating a new class under
  # Dtrace::Provider and implementing or overriding the required steps
  # in the build process.
  #
  # Firing probes is explained in Dtrace::Probe.
  #
  # There are some limitations:
  #
  # You cannot choose all the components of the probe name: you can
  # choose the provider and probe name, but the module and function
  # components will be derived by DTrace, and won't be meaningful
  # (they'll refer to the shim extension that gets created, not to
  # anything in your Ruby program). It seems unlikely it's possible to
  # change this. 
  #
  # You cannot currently set D attributes: they're hardcoded to a
  # default set. This will change. 
  #
  # The extension will currently be rebuilt every time the provider is
  # created, as there's not yet any support for packaging the provider
  # in some way. This will change, to something along the lines of
  # what RubyInline does to allow a pre-built extension to be used.
  #
  class Provider

    class BuildError < StandardError; end

    # Creates a DTrace provider. Causes a shim extension to be built
    # and loaded, implementing the probes. 
    #
    # Example:
    # 
    #   Dtrace::Provider.create :action_controller do |p|
    #     p.probe :process_start,  :string
    #     p.probe :process_finish, :string, :integer
    #   end
    #
    # The symbol passed to create becomes the name of the provider,
    # and the class exposed under Dtrace::Probe in Ruby (camelized, so
    # the above statement creates Dtrace::Probe::ActionController).
    # 
    # create yields a Provider for the current platform, on which you
    # can call probe, to create the individual probes. 
    # 
    def self.create(name)
      if RUBY_PLATFORM =~ /darwin/
        provider = Dtrace::Provider::OSX.new(name)
      else
        provider = Dtrace::Provider::Solaris.new(name)
      end
      yield provider
      provider.enable
    end

    # Creates a DTrace USDT probe. Arguments are the probe name, and
    # then the argument types it will accept. The following argument
    # types are supported:
    #
    # :string  (char *)
    # :integer (int)
    #
    # The probe will be named based on the provider name and the
    # probe's name:
    #
    #   provider_name:provider_name.so:probe_name:probe-name
    #
    # See the limitations explained elsewhere for an explanation of
    # this redundancy in probe names.
    #
    def probe(name, *types) 
      typemap = { :string => 'char *', :integer => 'int' } 
      @probes[name] = types.map {|t| typemap[t]} 
    end

    def initialize(name)
      @name   = name.to_s
      @class  = camelize(name)
      @probes = {}
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

        # Probe setup is split up for easy overriding
        definition
        header
        source
        ruby_object
        dtrace_object
        link
        load
      end
    end

    protected

    def run(cmd)
      result = `#{cmd}`
      if $? != 0
        raise BuildError.new("Error running:\n#{cmd}\n\n#{result}")
      end
    end

    def hdrdir
      %w(srcdir archdir).map { |name|
        dir = Config::CONFIG[name]
      }.find { |dir|
        dir and File.exist? File.join(dir, "/ruby.h")
      } or abort "ERROR: Can't find header dir for ruby. Exiting..."
    end

    private

    def camelize(lower_case_and_underscored_word)
      # Pinched from ActiveSupport's Inflector
      lower_case_and_underscored_word.to_s.gsub(/\/(.?)/) { "::" + $1.upcase }.gsub(/(^|_)(.)/) { $2.upcase }
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
      run "#{DTRACE} -h -s #{@tempdir}/probes.d -o #{@tempdir}/probes.h"
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
      # Load the generated extension with a full path (saves adjusting
      # $:) Done in the context of an anonymous class, since the
      # module does not itself define a class.  TODO: find a way of
      # doing this without string eval...
      lib = "#{@tempdir}/#{@name}"
      c = Class.new
      c.module_eval do 
        require lib
      end
      eval "Dtrace::Probe::#{@class} = c"
    end
    
  end
end
