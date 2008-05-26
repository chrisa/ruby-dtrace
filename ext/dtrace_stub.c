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

/*   char insns[FUNC_SIZE] = { 0x55, 0x89, 0xe5, 0x83, 0xec, 0x08, 0x83, 0xe4, 0xf0, 0xb8, 0x00, 0x00, */
/* 			    0x00, 0x00, 0x83, 0xc0, 0x0f, 0x83, 0xc0, 0x0f, 0xc1, 0xe8, 0x04, 0xc1, */
/* 			    0xe0, 0x04, 0x29, 0xc4, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc9, 0xc3 }; */

  char insns[FUNC_SIZE] = { 0x90, 0x90, 0x90, 0x90, 0x90,
			    0xc9, 0xc3 };

  stub = ALLOC(dtrace_stub_t);
  if (!stub) {
    rb_raise(eDtraceException, "alloc failed");
    return Qnil;
  }

  stub->mem  = NULL;
  stub->func = NULL;

  /* create stub function, get offset */ 
#ifdef __APPLE__
  if ((stub->mem = (void *)malloc(FUNC_SIZE)) < 0) {
#else
  if ((stub->mem = (void *)memalign(FUNC_SIZE, FUNC_SIZE)) < 0) {
#endif
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

VALUE dtracestub_addr(VALUE self) {
  dtrace_stub_t *stub;
  int ret;
  
  Data_Get_Struct(self, dtrace_stub_t, stub);
  return INT2FIX(stub->mem);
}

VALUE dtracestub_call(int argc, VALUE *ruby_argv, VALUE self) {
  dtrace_stub_t *stub;
  int i;
  void *argv[8]; // probe argc max for now.

  Data_Get_Struct(self, dtrace_stub_t, stub);

  /* munge Ruby values to either char *s or ints. */
  for (i = 0; i < argc; i++) {
    switch (TYPE(ruby_argv[i])) {
    case T_STRING:
      argv[i] = (void *)RSTRING(ruby_argv[i])->ptr;
      break;
    case T_FIXNUM:
      argv[i] = (void *)FIX2INT(ruby_argv[i]);
      break;
    default:
      rb_raise(eDtraceException, "type of arg[%d] is not string or fixnum", i);
      break;
    }
  }

  /* dispatch to stub: we're using C to build the arguments on the
   * stack for us here, so avoiding any argument handling in the stub
   * itself. 
   */
  switch (argc) {
  case 0:
    (void)(*stub->func)();
    break;
  case 1:
    (void)(*stub->func)(argv[0]);
    break;
  case 2:
    (void)(*stub->func)(argv[0], argv[1]);
    break;
  case 3:
    (void)(*stub->func)(argv[0], argv[1], argv[2]);
    break;
  case 4:
    (void)(*stub->func)(argv[0], argv[1], argv[2], argv[3]);
    break;
  case 5:
    (void)(*stub->func)(argv[0], argv[1], argv[2], argv[3], 
			argv[4]);
    break;
  case 6:
    (void)(*stub->func)(argv[0], argv[1], argv[2], argv[3],
			argv[4], argv[5]);
    break;
  case 7:
    (void)(*stub->func)(argv[0], argv[1], argv[2], argv[3],
			argv[4], argv[5], argv[6]);
    break;
  case 8:
    (void)(*stub->func)(argv[0], argv[1], argv[2], argv[3],
			argv[4], argv[5], argv[6], argv[7]);
    break;
  default:
    rb_raise(eDtraceException, "probe argc max is 8");
    break;
  }
  
  return Qnil;
}
