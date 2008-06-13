/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 80 /* 32 bytes of is_enabled, plus then good for 16
			arguments: 16 + 3 * argc */
#define IS_ENABLED_FUNC_LEN 48

/* :nodoc: */
VALUE dtraceprobe_init(VALUE self, VALUE rargc)
{
  dtrace_probe_t *probe;
  uint8_t *ip;
  int i;
  int argc = FIX2INT(rargc);

  Data_Get_Struct(self, dtrace_probe_t, probe);

  /* First initialise the is_enabled tracepoint */

  /* 9d e3 bf 98 01 00 00 00  |.........<E3><BF>.....|
00000110  90 10 00 00 10 80 00 02  d0 27 bf fc e0 07 bf fc  |........<D0>'<BF><FC><E0>.<BF><FC>|
00000120  b0 14 00 00 81 c7 e0 08  81 e8 00 00 

        [ 4]      108:  save        %sp, -104, %sp
        [ 4]      10c:  nop         
        [ 4]      110:  clr         %o0
        [ 4]      114:  ba          0x11c
        [ 4]      118:  st          %o0, [%fp - 4]
        [ 4]      11c:  ld          [%fp - 4], %l0
        [ 4]      120:  or          %l0, %g0, %i0
        [ 4]      124:  ret         
        [ 4]      128:  restore    
*/

  uint8_t insns[FUNC_SIZE] = {
    /* save        %sp, -104, %sp */
    0x9d, 0xe3, 0xbf, 0xa0, 
    /* nop */
    0x01, 0x00, 0x00, 0x00,   
    /* clr         %o0 */
    0x90, 0x10, 0x00, 0x00,
    /* ba          0x11c */
    0x10, 0x80, 0x00, 0x02,
    /* st          %o0, [%fp - 4] */
    0xd0, 0x27, 0xbf, 0xfc,
    /* ld          [%fp - 4], %l0 */
    0xe0, 0x07, 0xbf, 0xfc,
    /* or          %l0, %g0, %i0 */
    0xb0, 0x14, 0x00, 0x00,
    /* ret */
    0x81, 0xc7, 0xe0, 0x08, 
    /* restore */
    0x81, 0xe8, 0x00, 0x00,
    
    0x00, 0x01, 0x00, 0x00,   
    0x00, 0x01, 0x00, 0x00,   
    0x00, 0x01, 0x00, 0x00,   

    0x9d, 0xe3, 0xbf, 0x90, 
    0x82, 0x10, 0x20, 0x01, 
    0xb0, 0x10, 0x00, 0x01, 
    0x81, 0xc7, 0xe0, 0x08, 
    0x81, 0xe8, 0x00, 0x00,
    
    0x00, 0x01, 0x00, 0x00,   
    0x00, 0x01, 0x00, 0x00,   
    0x00, 0x01, 0x00, 0x00,   
  };

  /* allocate memory on a page boundary, for mprotect */
  probe->func = (void *)memalign(PAGESIZE, FUNC_SIZE);
  if (probe->func < 0) {
    rb_raise(eDtraceException, "malloc failed: %s\n", strerror(errno));
    return Qnil;
  }
  
  if ((mprotect((void *)probe->func, FUNC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC)) < 0) {
    rb_raise(eDtraceException, "mprotect failed: %s\n", strerror(errno));
    return Qnil;
  }
  
  if ((memcpy(probe->func, insns, FUNC_SIZE)) < 0) {
    rb_raise(eDtraceException, "memcpy failed: %s\n", strerror(errno));
    return Qnil;
  }    
  
  return self;
}

VALUE dtraceprobe_free(void *arg)
{
  dtrace_probe_t *probe = (dtrace_probe_t *)arg;
  
  if (probe) {
    free(probe);
  }
}
 
VALUE dtraceprobe_alloc(VALUE klass)
{
  VALUE obj;
  dtrace_probe_t *probe;

  probe = ALLOC(dtrace_probe_t);
  if (!probe) {
    rb_raise(eDtraceException, "alloc failed");
    return Qnil;
  }

  /* no mark function: no ruby objects hung off this struct */
  obj = Data_Wrap_Struct(klass, NULL, dtraceprobe_free, probe);
  return obj;
}

VALUE dtraceprobe_addr(VALUE self)
{
  dtrace_probe_t *probe;
  
  Data_Get_Struct(self, dtrace_probe_t, probe);
  return INT2FIX(probe->func);
}

VALUE dtraceprobe_is_enabled(VALUE self)
{
  dtrace_probe_t *probe;
  
  Data_Get_Struct(self, dtrace_probe_t, probe);
  return INT2FIX((int)(*probe->func)());
}

VALUE dtraceprobe_fire(int argc, VALUE *ruby_argv, VALUE self) {
  dtrace_probe_t *probe;
  int i;
  void *argv[8]; // probe argc max for now.
  void (*func)();

  Data_Get_Struct(self, dtrace_probe_t, probe);

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
  
  func = (void (*)())(probe->func + IS_ENABLED_FUNC_LEN);

  switch (argc) {
  case 0:
    (void)(*func)();
    break;
  case 1:
    (void)(*func)(argv[0]);
    break;
  case 2:
    (void)(*func)(argv[0], argv[1]);
    break;
  case 3:
    (void)(*func)(argv[0], argv[1], argv[2]);
    break;
  case 4:
    (void)(*func)(argv[0], argv[1], argv[2], argv[3]);
    break;
  case 5:
    (void)(*func)(argv[0], argv[1], argv[2], argv[3], 
		  argv[4]);
    break;
  case 6:
    (void)(*func)(argv[0], argv[1], argv[2], argv[3],
		  argv[4], argv[5]);
    break;
  case 7:
    (void)(*func)(argv[0], argv[1], argv[2], argv[3],
		  argv[4], argv[5], argv[6]);
    break;
  case 8:
    (void)(*func)(argv[0], argv[1], argv[2], argv[3],
		  argv[4], argv[5], argv[6], argv[7]);
    break;
  default:
    rb_raise(eDtraceException, "probe argc max is 8");
    break;
  }
  
  return Qnil;
}

VALUE dtraceprobe_probe_offset(VALUE self, VALUE rfile, VALUE argc)
{
  /*
   * compute offset into stub: see dtrace_probe.c
   *
   * 32 bytes - length of is_enabled function
   * +
   * 6 bytes - function entry
   * +
   * 3 bytes per argument - arg->stack push
   *
   */
  return INT2FIX(0);
}

VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE rfile)
{
  return INT2FIX(8);
}
