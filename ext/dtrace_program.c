/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDTraceException;
RUBY_EXTERN VALUE cDTraceProgramInfo;

/* :nodoc: */
VALUE dtraceprogram_init(VALUE self)
{
  dtrace_prog_t *prog;

  Data_Get_Struct(self, dtrace_prog_t, prog);
  return self;
}

/*
 * Execute the D program. Returns a DTraceProgramInfo object if
 * successful, otherwise raises a DTraceException.
 */
VALUE dtraceprogram_exec(VALUE self)
{
  dtrace_prog_t *prog;
  dtrace_proginfo_t *proginfo;
  dtrace_handle_t *handle;
  VALUE dtrace;
  VALUE dtraceprograminfo;
  int ret;

  Data_Get_Struct(self, dtrace_prog_t, prog);
  dtrace = rb_iv_get(self, "@handle");
  Data_Get_Struct(dtrace, dtrace_handle_t, handle);

  proginfo = ALLOC(dtrace_proginfo_t);
  if (!proginfo) {
    rb_raise(eDTraceException, "alloc failed");
    return Qnil;
  }

  ret = dtrace_program_exec(handle->hdl, prog, proginfo);

  if (ret == 0) {
    dtraceprograminfo = Data_Wrap_Struct(cDTraceProgramInfo, 0, NULL, proginfo);
    rb_iv_set(self, "@proginfo", dtraceprograminfo);
  }

  if (ret < 0)
          rb_raise(eDTraceException, "%s", dtrace_errmsg(handle->hdl, dtrace_errno(handle->hdl)));

  return Qnil;
}

/*
 * Return this program's DTraceProgramInfo object. Returns nil unless
 * the program has been executed.
 */
VALUE dtraceprogram_info(VALUE self)
{
  return rb_iv_get(self, "@proginfo");
}
