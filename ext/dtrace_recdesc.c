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

