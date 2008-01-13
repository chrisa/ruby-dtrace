require 'dtracer'
require 'dtracer_client'

module DtraceReport

  def self.included(base)
    base.extend DtraceMacro
  end

  module DtraceMacro
    def dtrace(enable=:on, options={})
      if enable == :on

        # Set tracer type, in-process or helper-process
        if options[:tracer] == :self
          tracer = Dtracer.new
        elsif options[:tracer] == :helper
          tracer = DtracerClient.new
        else
          raise "tracer option is self or helper"
        end

        # Set script, or default
        if options[:script]
          tracer.script = options[:script]
        else
          tracer.script = 'default.d'
        end

        tracer.logger = logger
        DtraceReport.tracer = tracer
      end
    end
  end

  attr_reader :dtrace_report
  attr_reader :dtrace_script

  protected
  def self.tracer=(tracer)
    @@tracer = tracer
  end

  def enable_dtrace
    @@tracer.start_dtrace($$)
  end

  def append_dtrace_report
    @dtrace_script = @@tracer.script
    @dtrace_report = @@tracer.end_dtrace
    # yuck!
    old_template_root = @template.base_path
    begin
      @template.view_paths =  File.expand_path(File.dirname(__FILE__) + '/../views')
      response.body.gsub!(/<\/body/, @template.render(:partial => 'dtrace/report') + '</body')
    ensure
      @template.view_paths = old_template_root
    end
  end
  
end
