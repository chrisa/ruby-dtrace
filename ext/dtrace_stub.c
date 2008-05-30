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

/*      3. void probe8(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7) { */
/*         <Function: probe8> */
/*         [ 3]  805133c:  pushl   %ebp */
/*         [ 3]  805133d:  movl    %esp,%ebp */
/*         [ 3]  805133f:  subl    $8,%esp */
/*      4.         TEST_TEST_INT_INT_INT_INT_INT_INT_INT_INT_PROBE(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7); */
/*         [ 4]  8051342:  pushl   0x24(%ebp) */
/*         [ 4]  8051345:  pushl   0x20(%ebp) */
/*         [ 4]  8051348:  pushl   0x1c(%ebp) */
/*         [ 4]  805134b:  pushl   0x18(%ebp) */
/*         [ 4]  805134e:  pushl   0x14(%ebp) */
/*         [ 4]  8051351:  pushl   0x10(%ebp) */
/*         [ 4]  8051354:  pushl   0xc(%ebp) */
/*         [ 4]  8051357:  pushl   8(%ebp) */
/*         [ 4]  805135a:  nop      */
/*         [ 4]  805135b:  nop      */
/*         [ 4]  805135c:  nop      */
/*         [ 4]  805135d:  nop      */
/*         [ 4]  805135e:  nop      */
/*         [ 4]  805135f:  addl    $0x20,%esp */
/*      5. } */
/*         [ 5]  8051362:  leave    */
/*         [ 5]  8051363:  ret      */

/* 1330                                       55 89 e5 83  .....^[. ....U... */
/* 1340  ec 08 ff 75 24 ff 75 20  ff 75 1c ff 75 18 ff 75  ...u$.u  .u..u..u */
/* 1350  14 ff 75 10 ff 75 0c ff  75 08 90 90 90 90 90 83  ..u..u.. u....... */
/* 1360  c4 20 c9 c3 */

  char insns[FUNC_SIZE] = 
    {
      0x55, 0x89, 0xe5, 0x83, 0xec, 0x08,
      0xff, 0x75, 0x24,
      0xff, 0x75, 0x20,
      0xff, 0x75, 0x1c,
      0xff, 0x75, 0x18,
      0xff, 0x75, 0x14,
      0xff, 0x75, 0x10,
      0xff, 0x75, 0x0c,
      0xff, 0x75, 0x08,
      0x90, 0x90, 0x90, 0x90, 0x90,
      0x83, 0xc4, 0x20,
      0xc9, 0xc3
    };

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
