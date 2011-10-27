/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

/* :nodoc: */
VALUE dtracerecdesc_init(VALUE self)
{
  dtrace_recdesc_t *recdesc;

  Data_Get_Struct(self, dtrace_recdesc_t, recdesc);
  return self;
}

/*
 * Returns the type of action which generated this recdesc.
 * (exit, printf, printa or "other" for all other actions).
 */
VALUE dtracerecdesc_action(VALUE self)
{
  dtrace_recdesc_t *recdesc;
  VALUE v;
  Data_Get_Struct(self, dtrace_recdesc_t, recdesc);

  if (recdesc){
    switch (recdesc->dtrd_action) {
    case DTRACEACT_EXIT:
      v = rb_str_new2("exit");
      break;
    case DTRACEACT_PRINTF:
      v = rb_str_new2("printf");
      break;
    case DTRACEACT_PRINTA:
      v = rb_str_new2("printa");
      break;
    default:
      v = rb_str_new2("other");
      break;
    }
    return v;
  }
  else {
    return Qnil;
  }
}
