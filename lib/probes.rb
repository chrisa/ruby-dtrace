require 'probes/action_controller'
ActionController::Base.class_eval do
  include Probes::ActionController
end
