#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

require 'dtrace/probe'
require 'dtrace/dof'

class Dtrace

  # A DTrace provider. Allows creation of USDT probes on a running
  # Ruby program. You can use this with a Ruby interpreter compiled
  # with the core DTrace probes, but you don't have to.
  #
  # Firing probes is explained in Dtrace::Probe.
  #
  class Provider
    include Dtrace::Dof::Constants

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
    def self.create(name)
      provider = Dtrace::Provider.new(name)
      yield provider
      provider.enable
    end

    def self.unload(name)
      
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
    #   provider_name:*:*:probe-name
    #
    #
    def probe(name, *types) 
      typemap = { :string => 'char *', :integer => 'int' } 
      @probe_defs[name] = types.map {|t| typemap[t]} 
    end

    def initialize(name)
      @name       = name.to_s
      @class      = camelize(name)
      @probe_defs = {}
    end

    def enable
      f = Dtrace::Dof::File.new
      strings = Array.new
      
      # Gather strings
      strings << @name
      strings << 'main' # XXX

      @probe_defs.each_key do |name|
        strings << name
      end

      @probe_defs.each_value do |p|
        p.each do |type|
          strings << type
        end
      end

      strtab = Dtrace::Dof::Section::Strtab.new(strings, 0)
      f.sections << strtab

      s = Dtrace::Dof::Section.new(DOF_SECT_PROBES, 1)
      probes = Array.new
      stubs = Hash.new
      @probe_defs.each_key do |name|
        probe = Dtrace::Probe.new
        probes <<
          {
          :name     => strtab.stridx(name),
          :func     => strtab.stridx('main'), # XXX
          :noffs    => 1,
          :enoffidx => 0,
          :argidx   => 0,
          :nenoffs  => 0,
          :offidx   => 0,
          :addr     => probe.addr,
          :nargc    => @probe_defs[name].length,
          :xargc    => @probe_defs[name].length,
        }
        
        stubs[name] = probe
      end
      s.data = probes
      f.sections << s

      s = Dtrace::Dof::Section.new(DOF_SECT_PRARGS, 2)
      s.data = Array.new
      @probe_defs.each_value do |args|
        args.each_with_index do |arg, i|
          s.data << (i + 1)
        end
      end
      if s.data.empty?
        s.data = [ 0 ]
      end
      f.sections << s

      s = Dtrace::Dof::Section.new(DOF_SECT_PROFFS, 3)
      s.data = [ 0 ]
      f.sections << s
      
      s = Dtrace::Dof::Section.new(DOF_SECT_PROVIDER, 4)
      s.data = {
        :strtab => 0,
        :probes => 1,
        :prargs => 2,
        :proffs => 3,
        :name => strtab.stridx(@name),
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

      dof = f.generate
      Dtrace.loaddof(dof)

      c = Class.new
      c.class_eval do
        @@probes = stubs
        def self.method_missing(name)
          unless @@probes[name].nil?
            yield @@probes[name]
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
