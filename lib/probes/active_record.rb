module Probes
  module ActiveRecord

    module ClassMethods
      def find_by_sql_with_probes(sql)
        Dtrace::Probe::ActionController.find_by_sql_start do |p|
          p.fire(sql)
        end
        results = find_by_sql_without_probes(sql)
        Dtrace::Probe::ActiveRecord.find_by_sql_finish do |p|
          p.fire(results.inspect)
        end
        results
      end
    end

    def self.included(base)
      base.extend ClassMethods

      Dtrace::Provider.create :active_record do |p|
        p.probe :find_by_sql_start,  :string
        p.probe :find_by_sql_finish, :string
      end
      
      base.class_eval do 
        class << self
          alias_method_chain :find_by_sql, :probes
        end
      end
    end

  end
end
