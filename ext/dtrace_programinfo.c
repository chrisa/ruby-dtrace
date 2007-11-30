/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

VALUE dtraceprograminfo_init(VALUE self)
{
  dtrace_proginfo_t *proginfo;

  Data_Get_Struct(self, dtrace_proginfo_t, proginfo);
  return self;
}

/*
 * Returns the number of aggregates associated with this program.
 */
VALUE dtraceprograminfo_aggregates_count(VALUE self) 
{
  dtrace_proginfo_t *proginfo;

  Data_Get_Struct(self, dtrace_proginfo_t, proginfo);
  return INT2NUM(proginfo->dpi_aggregates);
}

/*
 * Returns the number of record generating probes associated with this
 * program.
 */
VALUE dtraceprograminfo_recgens_count(VALUE self)
{
  dtrace_proginfo_t *proginfo;

  Data_Get_Struct(self, dtrace_proginfo_t, proginfo);
  return INT2NUM(proginfo->dpi_recgens);
}

/*
 * Returns the number of probes matched by this program.
 */
VALUE dtraceprograminfo_matches_count(VALUE self)
{
  dtrace_proginfo_t *proginfo;

  Data_Get_Struct(self, dtrace_proginfo_t, proginfo);
  return INT2NUM(proginfo->dpi_matches);
}

/*
 * Returns the number of speculations specified by this program.
 */
VALUE dtraceprograminfo_speculations_count(VALUE self)
{
  dtrace_proginfo_t *proginfo;

  Data_Get_Struct(self, dtrace_proginfo_t, proginfo);
  return INT2NUM(proginfo->dpi_speculations);
}

