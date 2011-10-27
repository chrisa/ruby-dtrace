/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;

/* :nodoc: */
VALUE dtraceerrdata_init(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);
  return self;
}

/* Returns the CPU which generated this err record */
VALUE dtraceerrdata_cpu(VALUE self)
{
  dtrace_errdata_t *data;
  processorid_t cpu;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    cpu = data->dteda_cpu;
    return INT2FIX(cpu);
  }
  else {
    return Qnil;
  }
}

/* Returns a the action producing the error */
VALUE dtraceerrdata_action(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    return INT2FIX(data->dteda_action);
  }
  else {
    return Qnil;
  }
}

/* Returns the offset of the error */
VALUE dtraceerrdata_offset(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    return INT2FIX(data->dteda_offset);
  }
  else {
    return Qnil;
  }
}

/* Returns fault represented by the error */
VALUE dtraceerrdata_fault(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    return INT2FIX(data->dteda_fault);
  }
  else {
    return Qnil;
  }
}

/* Returns the address of the fault if any */
VALUE dtraceerrdata_addr(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    return INT2FIX(data->dteda_addr);
  }
  else {
    return Qnil;
  }
}

/* Returns a message from the DTrace library describing this err
   record. */
VALUE dtraceerrdata_msg(VALUE self)
{
  dtrace_errdata_t *data;

  Data_Get_Struct(self, dtrace_errdata_t, data);

  if (data) {
    return rb_str_new2(data->dteda_msg);
  }
  else {
    return Qnil;
  }
}

