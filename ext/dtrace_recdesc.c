/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

VALUE dtracerecdesc_init(VALUE self)
{
  dtrace_recdesc_t *recdesc;

  Data_Get_Struct(self, dtrace_recdesc_t, recdesc);
  return self;
}

/*
 * Return the data for this record.
 */
VALUE dtracerecdesc_data(VALUE self)
{
  VALUE dtraceaggdata;
  dtrace_recdesc_t *recdesc;
  dtrace_aggdata_t *aggdata;

  Data_Get_Struct(self, dtrace_recdesc_t, recdesc);

  dtraceaggdata = rb_iv_get(self, "@aggdata");
  Data_Get_Struct(dtraceaggdata, dtrace_aggdata_t, aggdata);
  
  if (recdesc->dtrd_size == 256) {
    char *c = aggdata->dtada_data + recdesc->dtrd_offset;
    return rb_str_new2(c);
  }
  else {
    uint64_t n = *((uint64_t *)(aggdata->dtada_data + recdesc->dtrd_offset));
    return INT2FIX(n);
  }
}
