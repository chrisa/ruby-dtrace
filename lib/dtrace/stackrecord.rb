#
# Ruby-DTrace
# (c) 2007 Chris Andrews <chris@nodnol.org>
#

# A record representing the result of a stack() or ustack()
# action. Its value is a list of symbolic stack frames:
# 
#   #<DTraceStackRecord:0x14e24 @value=
#           ["libSystem.B.dylib`__sysctl+0xa",
#            "libdtrace.dylib`dt_aggregate_go+0x9a",
#            "dtrace_api.bundle`dtrace_hdl_go+0x30",
#            "libruby.1.dylib`rb_eval_string_wrap+0x40fd",
#            "libruby.1.dylib`rb_eval_string_wrap+0x4cdb",
#            ...
#            "libruby.1.dylib`rb_apply+0x392",
#            "libruby.1.dylib`rb_eval_string_wrap+0xe82"]>
#
class DTrace
  class StackRecord
    attr_reader :value

    # Given a stack as a string returned from DTrace, set the value of
    # this record to a list of stack frames.
    def parse(raw)
      frames = raw.split(/\n/)
      @value = frames.map {|f| f.lstrip }.select {|f| f.length > 0 }
    end

  end
end
