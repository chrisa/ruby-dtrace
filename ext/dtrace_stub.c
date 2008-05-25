/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 4096

VALUE dtracestub_alloc(VALUE klass)
{
  VALUE obj;
  dtrace_stub_t *stub;

  char insns[FUNC_SIZE] = { 0x55, 0x89, 0xe5, 0x83, 0xec, 0x08, 0x83, 0xe4, 0xf0, 0xb8, 0x00, 0x00,
			    0x00, 0x00, 0x83, 0xc0, 0x0f, 0x83, 0xc0, 0x0f, 0xc1, 0xe8, 0x04, 0xc1,
			    0xe0, 0x04, 0x29, 0xc4, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc9, 0xc3 };

  stub = ALLOC(dtrace_stub_t);
  if (!stub) {
    rb_raise(eDtraceException, "alloc failed");
    return Qnil;
  }

  stub->mem  = NULL;
  stub->func = NULL;

  /* create stub function, get offset */ 
  if ((stub->mem = (void *)memalign(FUNC_SIZE, FUNC_SIZE)) < 0) {
    rb_raise(eDtraceException, "malloc failed: %s\n", strerror(errno));
    return Qnil;
  }

  if ((mprotect(stub->mem, FUNC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC)) < 0) {
    rb_raise(eDtraceException, "mprotect failed: %s\n", strerror(errno));
    return Qnil;
  }
  
  if ((memcpy(stub->mem, insns, FUNC_SIZE)) < 0) {
    rb_raise(eDtraceException, "memcpy failed: %s\n", strerror(errno));
    return Qnil;
  }    

  stub->func = stub->mem;

  /* obj = Data_Wrap_Struct(klass, dtrace_hdl_mark, dtrace_hdl_free, handle); */
  obj = Data_Wrap_Struct(klass, NULL, NULL, stub);
  return obj;
}

VALUE dtracestub_call(VALUE self) {
  dtrace_stub_t *stub;
  
  Data_Get_Struct(self, dtrace_stub_t, stub);
  (void)(*stub->func)();
  
  return Qnil;
}

VALUE dtracestub_addr(VALUE self) {
  dtrace_stub_t *stub;
  int ret;
  
  Data_Get_Struct(self, dtrace_stub_t, stub);
  return INT2FIX(stub->mem);
}
