/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include <ruby.h>
#include <sys/dtrace.h>
#include <sys/utsname.h>
#include <sys/dtrace.h>

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

/* Struct to contain Dof::File allocated memory */
typedef struct dof_file {
  char *dof;
  uint32_t len;
  uint32_t offset;
} dof_file_t;

VALUE dof_parse(VALUE self, VALUE dof);

/* Section generate methods */
VALUE dof_generate_comments(VALUE self);
VALUE dof_generate_probes(VALUE self);
VALUE dof_generate_strtab(VALUE self);
VALUE dof_generate_utsname(VALUE self);
VALUE dof_generate_prargs(VALUE self);
VALUE dof_generate_proffs(VALUE self);
VALUE dof_generate_prenoffs(VALUE self);
VALUE dof_generate_provider(VALUE self);
VALUE dof_generate_reltab(VALUE self);
VALUE dof_generate_relhdr(VALUE self);

VALUE dof_generate_section_header(VALUE self);

VALUE dof_generate_header(VALUE self);
VALUE dof_header_len(VALUE self);

VALUE dof_file_alloc(VALUE klass);
VALUE dof_file_allocate_dof(VALUE self, VALUE size);
VALUE dof_file_append(VALUE self, VALUE data);
VALUE dof_file_addr(VALUE self);
VALUE dof_file_data(VALUE self);

VALUE dof_loaddof(VALUE self, VALUE dof, VALUE module_name);

