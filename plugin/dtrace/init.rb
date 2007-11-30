require 'dtrace_report'
ActionController::Base.class_eval do
  include DtraceReport
  before_filter :enable_dtrace if RAILS_ENV == 'development'
  after_filter :append_dtrace_report if RAILS_ENV == 'development'
end

