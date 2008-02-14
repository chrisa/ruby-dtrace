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

    # Overriding to fix the @rb_file breakage: For some reason the
    # stock RubyInline leaves the line number on the filename, then it
    # crashes trying to File.mtime it.
    def rb_file
      @rb_file.split(/:/)[0]
    end

    # Allow the module name to be set - normally you don't care, 
    # but we do here because it shows up in the probe name.
    def set_module_name(name)
      @module_name = name
    end
  end
end
