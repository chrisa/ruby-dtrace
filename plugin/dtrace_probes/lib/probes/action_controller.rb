module Probes
  module ActionController

    def process_with_probes(request, response, method = :perform_action, *arguments)
      Dtrace::Probe::ActionController.process_start do |p|
        p.fire(request.url)
      end
      process_without_probes(request, response, method, *arguments)
      Dtrace::Probe::ActionController.process_finish do |p|
        p.fire(response.content_type, response.body.size)
      end
      response
    end

    def self.included(base)
      Dtrace::Provider.create :action_controller do |p|
        p.probe :process_start,  :string
        p.probe :process_finish, :string, :integer
      end
      
      base.alias_method_chain :process, :probes
    end
    
  end
end
