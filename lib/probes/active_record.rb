module Probes
  module ActiveRecord

    module Base
      module ClassMethods
        def find_by_sql_with_probes(sql)
          Dtrace::Probe::ActionController.find_by_sql_start do |p|
            p.fire(sql)
          end
          results = find_by_sql_without_probes(sql)
          Dtrace::Probe::ActiveRecord.find_by_sql_finish do |p|
            p.fire(results.length)
          end
          results
        end
      end

      def self.included(base)
        base.extend ClassMethods

        Dtrace::Provider.create :active_record do |p|
          p.probe :find_by_sql_start,  :string
          p.probe :find_by_sql_finish, :integer
        end
        
        base.class_eval do 
          class << self
            alias_method_chain :find_by_sql, :probes
          end
        end
      end
    end

    module ConnectionAdapters
      module MysqlAdapter

        def execute_with_probes(sql, name = nil)
          Dtrace::Probe::ActiveRecordMysql.execute_start do |p|
            p.fire(sql)
          end
          results = execute_without_probes(sql, name)
          Dtrace::Probe::ActiveRecordMysql.execute_finish do |p|
            p.fire(results.inspect)
          end
          results
        end

        def self.included(base)
          Dtrace::Provider.create :active_record_mysql do |p|
            p.probe :execute_start,  :string
            p.probe :execute_finish, :string
          end
          
          base.alias_method_chain :execute, :probes
        end
        
      end
    end

  end
end
