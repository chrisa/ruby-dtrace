/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

/* :nodoc: */
VALUE dtraceprobedesc_init(VALUE self)
{
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  return self;
}

/*
 * Returns the id of the probedesc. Corresponds to the ID displayed by
 * dtrace -l
 */
VALUE dtraceprobedesc_probe_id(VALUE self)
{
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  return INT2NUM(pdp->dtpd_id);
}

/*
 * Returns the name of the probe's provider.
 */
VALUE dtraceprobedesc_provider(VALUE self)
{
  VALUE string;
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  string = rb_str_new2(pdp->dtpd_provider);
  return string;
}

/*
 * Returns the name of the module where the probe is defined.
 */
VALUE dtraceprobedesc_mod(VALUE self)
{
  VALUE string;
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  string = rb_str_new2(pdp->dtpd_mod);
  return string;
}

/*
 * Returns the name of the function where the probe is defined.
 */
VALUE dtraceprobedesc_func(VALUE self)
{
  VALUE string;
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  string = rb_str_new2(pdp->dtpd_func);
  return string;
}

/*
 * Returns the name of the probe.
 */
VALUE dtraceprobedesc_name(VALUE self)
{
  VALUE string;
  dtrace_probedesc_t *pdp;

  Data_Get_Struct(self, dtrace_probedesc_t, pdp);
  string = rb_str_new2(pdp->dtpd_name);
  return string;
}
