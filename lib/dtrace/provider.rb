#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace'
require 'dtrace/dof'
require 'dtrace/probe'
require 'dtrace/provider/probedef'

class Dtrace

  # A DTrace provider. Allows creation of USDT probes on a running
  # Ruby program. You can use this with a Ruby interpreter compiled
  # with the core DTrace probes, but you don't have to.
  #
  # Firing probes is explained in Dtrace::Probe.
  #
  class Provider
    include Dtrace::Dof::Constants

    Typemap = { :string => 'char *', :integer => 'int' } 

    # Creates a DTrace provider.
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
    # You can override the module name in the created probes, by
    # passing in an hash:
    #
    #   Dtrace::Provider.create :foo, { :module => 'somemodule' } do |p|
    #     p.probe...
    #   end
    def self.create(name, options={})
      options[:module] ||= 'ruby'
      provider = Dtrace::Provider.new(name, options[:module])
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
    # Providing an options hash as the second argument allows you to
    # override the function name, otherwise it will be taken from the
    # caller of this function:
    #
    #   p.probe :foo, { :function => 'somefunction' }, :int, ...
    #
    def probe(name, *types) 
      options = {}
      if types[0].respond_to? :keys
        options = types.shift
      end
      caller = Kernel.caller[0].match(/`(.*)'/)
      if caller
        options[:function] ||= caller[1]
      else
        options[:function] ||= name
      end

      pd = Dtrace::Provider::ProbeDef.new(name, options[:function])
      types.each do |t|
        if Typemap[t].nil?
          raise Dtrace::Exception.new("type '#{t}' invalid")
        else
          pd.args << Typemap[t]
        end
      end

      @probe_defs << pd
    end

    def initialize(provider_name, module_name)
      @name       = provider_name.to_s
      @module     = module_name.to_s
      @class      = camelize(provider_name)
      @probe_defs = []
    end

    def enable
      f = Dtrace::Dof::File.new
      
      strtab = Dtrace::Dof::Section::Strtab.new(0)
      f.sections << strtab

      s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
      probes = Array.new
      stubs = Hash.new
      argidx = 0
      offidx = 0
      @probe_defs.each do |pd|
        argc = pd.argc
        
        argv = 0
        pd.args.each do |type|
          i = strtab.add(type)
          argv = i if argv == 0
        end
        
        probe = Dtrace::Probe.new(argc)
        probes <<
          {
          :name     => strtab.add(pd.name),
          :func     => strtab.add(pd.function),
          :noffs    => 1,
          :enoffidx => offidx,
          :argidx   => argidx,
          :nenoffs  => 1,
          :offidx   => offidx,
          :addr     => probe.addr,
          :nargc    => argc,
          :xargc    => argc,
          :nargv    => argv,
          :xargv    => argv,
        }
        
        stubs[pd.name] = probe
        argidx += argc
        offidx += 1
      end
      s.data = probes
      f.sections << s

      s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
      s.data = Array.new
      @probe_defs.each do |pd|
        pd.args.each_with_index do |arg, i|
          s.data << i
        end
      end
      if s.data.empty?
        s.data = [ 0 ]
      end
      f.sections << s

      s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
      s.data = Array.new
      @probe_defs.each do |pd|
        s.data << stubs[pd.name].probe_offset(f.addr, pd.argc)
      end
      if s.data.empty?
        s.data = [ 0 ]
      end
      f.sections << s

      s = Dtrace::Dof::Section.new(DOF_SECT_PRENOFFS, 4)
      s.data = Array.new
      @probe_defs.each do |pd|
        s.data << stubs[pd.name].is_enabled_offset(f.addr)
      end
      if s.data.empty?
        s.data = [ 0 ]
      end
      f.sections << s
      
      s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 5)
      s.data = {
        :strtab => 0,
        :probes => 1,
        :prargs => 2,
        :proffs => 3,
        :prenoffs => 4,
        :name => strtab.add(@name),
        :provattr => { 
          :name  => DTRACE_STABILITY_EVOLVING,
          :data  => DTRACE_STABILITY_EVOLVING,
          :class => DTRACE_STABILITY_EVOLVING 
        },
        :modattr  => { 
          :name => DTRACE_STABILITY_PRIVATE,
          :data => DTRACE_STABILITY_PRIVATE,
          :class => DTRACE_STABILITY_EVOLVING 
        },
        :funcattr => { 
          :name => DTRACE_STABILITY_PRIVATE,
          :data => DTRACE_STABILITY_PRIVATE,
          :class => DTRACE_STABILITY_EVOLVING
        },
        :nameattr => { 
          :name => DTRACE_STABILITY_EVOLVING,
          :data => DTRACE_STABILITY_EVOLVING,
          :class => DTRACE_STABILITY_EVOLVING
        },
        :argsattr => {
          :name => DTRACE_STABILITY_EVOLVING,
          :data => DTRACE_STABILITY_EVOLVING,
          :class => DTRACE_STABILITY_EVOLVING
        },
      }
      f.sections << s
      
      f.generate
      Dtrace::Dof.loaddof(f, @module)

      c = Class.new
      c.class_eval do
        @@probes = stubs
        def self.method_missing(name)
          name = name.to_s
          unless @@probes[name].nil?
            if @@probes[name].is_enabled?
              yield @@probes[name]
            end
          end
        end
      end
      eval "Dtrace::Probe::#{@class} = c"

    end

    private

    def camelize(lower_case_and_underscored_word)
      # Pinched from ActiveSupport's Inflector
      lower_case_and_underscored_word.to_s.gsub(/\/(.?)/) { "::" + $1.upcase }.gsub(/(^|_)(.)/) { $2.upcase }
    end
    
  end
end
