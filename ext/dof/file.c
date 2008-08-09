/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

RUBY_EXTERN eDtraceDofException;

static VALUE dof_file_free(void *arg)
{
  dof_file_t *file = (dof_file_t *)arg;

  if (file) {
    free(file->dof);
    free(file);
  }
}

/* :nodoc: */
VALUE dof_file_alloc(VALUE klass)
{
  VALUE obj;
  dof_file_t *file;

  file = (dof_file_t *)ALLOC(dof_file_t);
  if (file == NULL) {
    rb_raise(eDtraceDofException, "failed to allocate dof_file_t");
    return Qnil;
  }
  file->dof = NULL;
  file->len = 0;
  file->offset = 0;
  
  obj = Data_Wrap_Struct(klass, NULL, dof_file_free, file);
  return obj;
}

/* :nodoc: */
VALUE dof_file_allocate_dof(VALUE self, VALUE size)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);

  file->len = FIX2INT(size);
  file->dof = (char *)ALLOC_N(char, file->len);
  if (file->dof == NULL) {
    rb_raise(eDtraceDofException, "failed to allocate %d bytes for DOF", file->len);
    return Qnil;
  }

  return Qnil;
}

/* Appends the given string to the DOF file. */
VALUE dof_file_append(VALUE self, VALUE data)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);

  if ((file->offset + RSTRING(data)->len) > file->len) {
    rb_raise(eDtraceDofException, "DOF allocation insufficient: %d > %d",
	     (file->offset + RSTRING(data)->len), file->len);
    return Qnil;
  }
  
  memcpy((file->dof + file->offset), RSTRING(data)->ptr, RSTRING(data)->len);
  file->offset += RSTRING(data)->len;
}

/* Returns the memory address of the DOF file. */
VALUE dof_file_addr(VALUE self)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);
  if (file->dof == NULL) {
    rb_raise(eDtraceDofException, "must allocate DOF buffer before calling addr");
    return Qnil;
  }
  return INT2FIX(file->dof);
}

/* Returns the DOF itself. */
VALUE dof_file_data(VALUE self)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);
  return rb_str_new(file->dof, file->offset);
}  

