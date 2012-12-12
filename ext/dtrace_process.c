/* Ruby-Dtrace
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

/* :nodoc: */
void dtrace_process_release(dtrace_process_t *process)
{
  //dtrace_proc_release(process->handle, process->proc);
  free(process);
}

/*
 * Start or restart the process. Call this having configured tracing
 * for the process, using $target in the D program.
 */
VALUE dtrace_process_continue(VALUE self)
{
  dtrace_process_t *process;

  Data_Get_Struct(self, dtrace_process_t, process);
  dtrace_proc_continue(process->handle, process->proc);

  return Qnil;
}
