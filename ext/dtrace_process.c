/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

/* :nodoc: */
VALUE dtrace_process_init(VALUE self)
{
  struct ps_prochandle *P;

  Data_Get_Struct(self, struct ps_prochandle, P);
  if (P)
    return self;
  else
    return Qnil;
}

/*
 * Start or restart the process. Call this having configured tracing
 * for the process, using $target in the D program.
 */
VALUE dtrace_process_continue(VALUE self)
{
  struct ps_prochandle *P;
  dtrace_hdl_t *handle;
  VALUE dtrace;
  
  Data_Get_Struct(self, struct ps_prochandle, P);

  dtrace = rb_iv_get(self, "@dtrace");
  Data_Get_Struct(dtrace, dtrace_hdl_t, handle);
  
  dtrace_proc_continue(handle, P);
}

