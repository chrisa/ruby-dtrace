#
# Ruby-Dtrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

class Dtrace
  class ProbeDesc

    def to_s
      "#{provider}:#{mod}:#{func}:#{name}"
    end

  end
end

