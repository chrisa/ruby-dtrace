/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

/* :nodoc: */
VALUE dtrace_process_init(VALUE self)
{
  dtrace_process_t *process;

  Data_Get_Struct(self, dtrace_process_t, process);
  if (process)
    return self;
  else
    return Qnil;
}

static void _release_process(dtrace_process_t *process)
{
  if (process->handle->hdl != NULL && process->proc != NULL) {
    dtrace_proc_release(process->handle->hdl, process->proc);
    process->proc = NULL;
  }
}

/* :nodoc: */
void dtrace_process_free(dtrace_process_t *process)
{
  _release_process(process);
  free(process);
}

/* Release the traced process. */
VALUE dtrace_process_release(VALUE self)
{
  dtrace_process_t *process;

  Data_Get_Struct(self, dtrace_process_t, process);
  _release_process(process);
  return Qnil;
}

/*
 * Start or restart the process. Call this having configured tracing
 * for the process, using $target in the D program.
 */
VALUE dtrace_process_continue(VALUE self)
{
  dtrace_process_t *process;

  Data_Get_Struct(self, dtrace_process_t, process);
  dtrace_proc_continue(process->handle->hdl, process->proc);

  return Qnil;
}
