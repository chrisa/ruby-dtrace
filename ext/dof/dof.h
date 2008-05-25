/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include <ruby.h>
#include <sys/dtrace.h>
#include <sys/utsname.h>

/* Handle missing RARRAY_LEN etc */
#ifdef RARRAY_LEN
static inline long   rb_str_len(VALUE s) {return RSTRING_LEN(s);}
static inline char  *rb_str_ptr(VALUE s) {return RSTRING_PTR(s);}
static inline long   rb_ary_len(VALUE s) {return  RARRAY_LEN(s);}
static inline VALUE *rb_ary_ptr(VALUE s) {return  RARRAY_PTR(s);}
#else
static inline long   rb_str_len(VALUE s) {return RSTRING(s)->len;}
static inline char  *rb_str_ptr(VALUE s) {return RSTRING(s)->ptr;}
static inline long   rb_ary_len(VALUE s) {return  RARRAY(s)->len;}
static inline VALUE *rb_ary_ptr(VALUE s) {return  RARRAY(s)->ptr;}
#endif // RARRAY_LEN

VALUE dof_parse(VALUE self, VALUE dof);

/* Section generate methods */
VALUE dof_generate_comments(VALUE self);
VALUE dof_generate_probes(VALUE self);
VALUE dof_generate_strtab(VALUE self);
VALUE dof_generate_utsname(VALUE self);
VALUE dof_generate_prargs(VALUE self);
VALUE dof_generate_proffs(VALUE self);
VALUE dof_generate_provider(VALUE self);
VALUE dof_generate_reltab(VALUE self);
VALUE dof_generate_relhdr(VALUE self);

VALUE dof_generate_section_header(VALUE self);

VALUE dof_generate_header(VALUE self);
VALUE dof_header_len(VALUE self);
