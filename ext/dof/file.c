/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

RUBY_EXTERN eDtraceDofException;

static VALUE dof_file_free(void *arg)
{
  dof_file_t *file = (dof_file_t *)arg;
  if (file)
    free(file);
}

/* :nodoc: */
VALUE dof_file_alloc(VALUE klass)
{
  VALUE obj;
  dof_file_t *file;

  file = ALLOC(dof_file_t);
  file->dof = (char *)ALLOC_N(char, 4096);
  file->offset = 0;
  
  obj = Data_Wrap_Struct(klass, NULL, dof_file_free, file);
  return obj;
}

/* Appends the given string to the DOF file. */
VALUE dof_file_append(VALUE self, VALUE data)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);
  
  memcpy((file->dof + file->offset), RSTRING(data)->ptr, RSTRING(data)->len);
  file->offset += RSTRING(data)->len;
}

/* Returns the memory address of the DOF file. */
VALUE dof_file_addr(VALUE self)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);
  return INT2FIX(file->dof);
}

/* Returns the DOF itself. */
VALUE dof_file_data(VALUE self)
{
  dof_file_t *file;
  Data_Get_Struct(self, dof_file_t, file);
  return rb_str_new(file->dof, file->offset);
}  

