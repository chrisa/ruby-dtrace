/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 96 /* 32 bytes of is_enabled, plus then good for 16
			arguments: 16 + 3 * argc */
#define IS_ENABLED_FUNC_LEN 32

/* :nodoc: */
VALUE dtraceprobe_init(VALUE self, VALUE rargc)
{
  dtrace_probe_t *probe;
  uint8_t *ip;
  int i;
  int argc = FIX2INT(rargc);

  Data_Get_Struct(self, dtrace_probe_t, probe);

  /* First initialise the is_enabled tracepoint */
  uint8_t insns[FUNC_SIZE] = {
    0x55, 0x89, 0xe5, 0x83, 0xec, 0x08,
    0x33, 0xc0,
    0x90, 0x90, 0x90,
    0x89, 0x45, 0xfc, 0x83, 0x7d, 0xfc,
    0x00, 0x0f, 0x95, 0xc0, 0x0f, 0xb6,
    0xc0, 0x89, 0x45, 0xfc, 0x8b, 0x45,
    0xfc, 
    0xc9, 0xc3
  };

#define OP_PUSHL_EBP     0x55
#define OP_MOVL_ESP_EBP  0x89, 0xe5
#define OP_SUBL_N_ESP    0x83, 0xec
#define OP_PUSHL_N_EBP_U 0xff
#define OP_PUSHL_N_EBP_L 0x75
#define OP_NOP           0x90
#define OP_ADDL_ESP_U    0x83
#define OP_ADDL_ESP_L    0xc4
#define OP_LEAVE         0xc9
#define OP_RET           0xc3

  /* Set up probe function */
  ip = insns + IS_ENABLED_FUNC_LEN;

  uint8_t func_in[7] = {
    OP_PUSHL_EBP, OP_MOVL_ESP_EBP, OP_SUBL_N_ESP, 0x08, NULL

  };
  
  uint8_t func_out[3] = {
    OP_LEAVE, OP_RET, NULL
  };
  
  for (i = 0; func_in[i]; i++)
    *ip++ = func_in[i];

  for (i = (4 + 4*argc); i >= 0x08; i -= 4) {
    *ip++ = OP_PUSHL_N_EBP_U;
    *ip++ = OP_PUSHL_N_EBP_L;
    *ip++ = i;
  }

  for (i = 0; i <=5; i++)
    *ip++ = OP_NOP;

  *ip++ = OP_ADDL_ESP_U;
  *ip++ = OP_ADDL_ESP_L;
  *ip++ = argc * 4;
  
  for (i = 0; func_out[i]; i++)
    *ip++ = func_out[i];

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
  return ((int)(*probe->func)()) ? Qtrue : Qfalse;
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
  return INT2FIX(32 + 6 + FIX2INT(argc) * 3);
}

VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE rfile)
{
  return INT2FIX(8);
}
