#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace
  class Provider
    class ProbeDef
      attr_reader :name, :function
      attr_accessor :args

      def initialize(name, function)
        @name = name.to_sym
        @function = function.to_s
        @args = []
      end

      def argc
        @args.length
      end

    end
  end
end
