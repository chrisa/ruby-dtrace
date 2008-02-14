require 'probes/action_controller'
ActionController::Base.class_eval do
  include Probes::ActionController
end

require 'probes/active_record'
ActiveRecord::Base.class_eval do
  include Probes::ActiveRecord
end
