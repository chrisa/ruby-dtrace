/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

void 
_init_constants(VALUE dtrace_dof)
{
  VALUE c = rb_define_module_under(dtrace_dof, "Constants");

  rb_define_const(c, "DOF_SECT_NONE",      INT2FIX(DOF_SECT_NONE));
  rb_define_const(c, "DOF_SECT_COMMENTS",  INT2FIX(DOF_SECT_COMMENTS));
  rb_define_const(c, "DOF_SECT_SOURCE",    INT2FIX(DOF_SECT_SOURCE));
  rb_define_const(c, "DOF_SECT_ECBDESC",   INT2FIX(DOF_SECT_ECBDESC));
  rb_define_const(c, "DOF_SECT_PROBEDESC", INT2FIX(DOF_SECT_PROBEDESC));
  rb_define_const(c, "DOF_SECT_ACTDESC",   INT2FIX(DOF_SECT_ACTDESC));
  rb_define_const(c, "DOF_SECT_DIFOHDR",   INT2FIX(DOF_SECT_DIFOHDR));
  rb_define_const(c, "DOF_SECT_DIF",       INT2FIX(DOF_SECT_DIF));
  rb_define_const(c, "DOF_SECT_STRTAB",    INT2FIX(DOF_SECT_STRTAB));
  rb_define_const(c, "DOF_SECT_VARTAB",    INT2FIX(DOF_SECT_VARTAB));
  rb_define_const(c, "DOF_SECT_RELTAB",    INT2FIX(DOF_SECT_RELTAB));
  rb_define_const(c, "DOF_SECT_TYPTAB",    INT2FIX(DOF_SECT_TYPTAB));
  rb_define_const(c, "DOF_SECT_URELHDR",   INT2FIX(DOF_SECT_URELHDR));
  rb_define_const(c, "DOF_SECT_KRELHDR",   INT2FIX(DOF_SECT_KRELHDR));
  rb_define_const(c, "DOF_SECT_OPTDESC",   INT2FIX(DOF_SECT_OPTDESC));
  rb_define_const(c, "DOF_SECT_PROVIDER",  INT2FIX(DOF_SECT_PROVIDER));
  rb_define_const(c, "DOF_SECT_PROBES",    INT2FIX(DOF_SECT_PROBES));
  rb_define_const(c, "DOF_SECT_PRARGS",    INT2FIX(DOF_SECT_PRARGS));
  rb_define_const(c, "DOF_SECT_PROFFS",    INT2FIX(DOF_SECT_PROFFS));
  rb_define_const(c, "DOF_SECT_INTTAB",    INT2FIX(DOF_SECT_INTTAB));
  rb_define_const(c, "DOF_SECT_UTSNAME",   INT2FIX(DOF_SECT_UTSNAME));
  rb_define_const(c, "DOF_SECT_XLTAB",     INT2FIX(DOF_SECT_XLTAB));
  rb_define_const(c, "DOF_SECT_XLMEMBERS", INT2FIX(DOF_SECT_XLMEMBERS));
  rb_define_const(c, "DOF_SECT_XLIMPORT",  INT2FIX(DOF_SECT_XLIMPORT));
  rb_define_const(c, "DOF_SECT_XLEXPORT",  INT2FIX(DOF_SECT_XLEXPORT));
  rb_define_const(c, "DOF_SECT_PREXPORT",  INT2FIX(DOF_SECT_PREXPORT));
  rb_define_const(c, "DOF_SECT_PRENOFFS",  INT2FIX(DOF_SECT_PRENOFFS));

  rb_define_const(c, "DTRACE_STABILITY_INTERNAL",  INT2FIX(DTRACE_STABILITY_INTERNAL));
  rb_define_const(c, "DTRACE_STABILITY_PRIVATE",   INT2FIX(DTRACE_STABILITY_PRIVATE));
  rb_define_const(c, "DTRACE_STABILITY_OBSOLETE",  INT2FIX(DTRACE_STABILITY_OBSOLETE));
  rb_define_const(c, "DTRACE_STABILITY_EXTERNAL",  INT2FIX(DTRACE_STABILITY_EXTERNAL));
  rb_define_const(c, "DTRACE_STABILITY_UNSTABLE",  INT2FIX(DTRACE_STABILITY_UNSTABLE));
  rb_define_const(c, "DTRACE_STABILITY_EVOLVING",  INT2FIX(DTRACE_STABILITY_EVOLVING));
  rb_define_const(c, "DTRACE_STABILITY_STABLE",    INT2FIX(DTRACE_STABILITY_STABLE));
  rb_define_const(c, "DTRACE_STABILITY_STANDARD",  INT2FIX(DTRACE_STABILITY_STANDARD));
}
