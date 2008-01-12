require 'dtracer'
require 'dtracer_client'

module DtraceReport

  def self.included(base)
    base.extend DtraceMacro
  end

  module DtraceMacro
    def dtrace(enable=:on, options={})
      if enable == :on
        if options[:tracer] == :self
          DtraceReport.tracer = Dtracer.new
        elsif options[:tracer] == :helper
          DtraceReport.tracer = DtracerClient.new
        else
          raise "tracer option is self or helper"
        end
      end
    end
  end

  attr_reader :dtrace_report

  protected
  def self.tracer=(tracer)
    @@tracer = tracer
  end
  
  def enable_dtrace
    @@tracer.start_dtrace($$)
  end

  def append_dtrace_report
    @dtrace_report = @@tracer.end_dtrace
    # yuck!
    old_template_root = @template.base_path
    begin
      @template.view_paths = File.join(RAILS_ROOT, 'vendor/plugins/dtrace/views')
      response.body.gsub!(/<\/body/, @template.render(:partial => 'dtrace/report') + '</body')
    ensure
      @template.view_paths = old_template_root
    end
  end
  
end
