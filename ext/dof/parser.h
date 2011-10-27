/*
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include <ruby.h>
#include <sys/dtrace.h>
#include <sys/utsname.h>

static VALUE dof_parse(VALUE self, VALUE dof);
