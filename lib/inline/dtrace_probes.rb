require 'inline'

# Monkeypatch Inline::C to override MAGIC_ARITY
# (we happen to want -2, it does -1 only)
module Inline
  class C
    MAGIC_ARITY = -2
  end
end

module Inline
  class DtraceProbes < Inline::C
    def set_module_name(name)
      @module_name = name
    end
  end
end
