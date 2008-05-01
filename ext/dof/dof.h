/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include <ruby.h>
#include <sys/dtrace.h>
#include <sys/utsname.h>

VALUE dof_parse(VALUE self, VALUE dof);

/* Section generate methods */
VALUE dof_generate_comments(VALUE self);
VALUE dof_generate_probes(VALUE self);
VALUE dof_generate_strtab(VALUE self);
VALUE dof_generate_utsname(VALUE self);
VALUE dof_generate_prargs(VALUE self);
VALUE dof_generate_proffs(VALUE self);
VALUE dof_generate_provider(VALUE self);

VALUE dof_generate_section_header(VALUE self);

VALUE dof_generate_header(VALUE self);
