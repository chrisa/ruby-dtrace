/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;

/* :nodoc: */
VALUE dtracedropdata_init(VALUE self)
{
  dtrace_dropdata_t *data;

  Data_Get_Struct(self, dtrace_dropdata_t, data);
  return self;
}

/* Returns the CPU which generated this drop record */
VALUE dtracedropdata_cpu(VALUE self)
{
  dtrace_dropdata_t *data;
  processorid_t cpu;

  Data_Get_Struct(self, dtrace_dropdata_t, data);
  
  if (data) {
    cpu = data->dtdda_cpu;
    return INT2FIX(cpu);
  }
  else {
    return Qnil;
  }
}

/* Returns the number of records dropped in this drop record */
VALUE dtracedropdata_drops(VALUE self)
{
  dtrace_dropdata_t *data;

  Data_Get_Struct(self, dtrace_dropdata_t, data);
  
  if (data) {
    return INT2FIX(data->dtdda_drops);
  }
  else {
    return Qnil;
  }
}

/* Returns the number of records dropped in total */
VALUE dtracedropdata_total(VALUE self)
{
  dtrace_dropdata_t *data;

  Data_Get_Struct(self, dtrace_dropdata_t, data);
  
  if (data) {
    return INT2FIX(data->dtdda_total);
  }
  else {
    return Qnil;
  }
}

/* Returns a message from the DTrace library describing this drop
   record. */
VALUE dtracedropdata_msg(VALUE self)
{
  dtrace_dropdata_t *data;
  
  Data_Get_Struct(self, dtrace_dropdata_t, data);
  
  if (data) {
    return rb_str_new2(data->dtdda_msg);
  }
  else {
    return Qnil;
  }
}

/* Returns the reason for the drop (the "drop kind") */
VALUE dtracedropdata_kind(VALUE self)
{
  dtrace_dropdata_t *data;
  VALUE kind;

  Data_Get_Struct(self, dtrace_dropdata_t, data);
  
  if (data) {
    switch (data->dtdda_kind) {
    case DTRACEDROP_PRINCIPAL:
      kind = rb_str_new2("drop to principal buffer");
      break;
    case DTRACEDROP_AGGREGATION:
      kind = rb_str_new2("drop to aggregation buffer");
      break;
    case DTRACEDROP_DYNAMIC:			
      kind = rb_str_new2("dynamic drop");
      break;
    case DTRACEDROP_DYNRINSE:			
      kind = rb_str_new2("dyn drop due to rinsing");
      break;
    case DTRACEDROP_DYNDIRTY:
      kind = rb_str_new2("dyn drop due to dirty");
      break;
    case DTRACEDROP_SPEC:
      kind = rb_str_new2("speculative drop");
      break;
    case DTRACEDROP_SPECBUSY:
      kind = rb_str_new2("spec drop due to busy");
      break;
    case DTRACEDROP_SPECUNAVAIL:
      kind = rb_str_new2("spec drop due to unavail");
      break;
    case DTRACEDROP_STKSTROVERFLOW:
      kind = rb_str_new2("stack string tab overflow");
      break;
    case DTRACEDROP_DBLERROR:
      kind = rb_str_new2("error in ERROR probe");
      break;
    default:
      kind = rb_str_new2("unknown");
      break;
    }
    return kind;
  }
  else {
    return Qnil;
  }
}
  
