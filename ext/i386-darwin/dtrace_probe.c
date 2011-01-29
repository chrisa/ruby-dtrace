/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 128 /* 32 bytes of is_enabled, plus then good for 16
			 arguments: 16 + 7 * argc */
#define IS_ENABLED_FUNC_LEN 32

/* :nodoc: */
VALUE 
dtraceprobe_init(VALUE self, VALUE rargc)
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
    0xc9, 0xc3
  };

#define OP_PUSHL_EBP      0x55
#define OP_MOVL_ESP_EBP_U 0x89
#define OP_MOVL_ESP_EBP_L 0xe5
#define OP_SUBL_N_ESP_U   0x83
#define OP_SUBL_N_ESP_L   0xec
#define OP_PUSHL_N_EBP_U  0xff
#define OP_PUSHL_N_EBP_L  0x75
#define OP_NOP            0x90
#define OP_ADDL_ESP_U     0x83
#define OP_ADDL_ESP_L     0xc4
#define OP_LEAVE          0xc9
#define OP_RET            0xc3
#define OP_MOVL_EAX_U     0x8b
#define OP_MOVL_EAX_L     0x45
#define OP_MOVL_ESP       0x89

  /* Set up probe function */
  ip = insns + IS_ENABLED_FUNC_LEN;

  *ip++ = OP_PUSHL_EBP;
  *ip++ = OP_MOVL_ESP_EBP_U;
  *ip++ = OP_MOVL_ESP_EBP_L;
  *ip++ = OP_SUBL_N_ESP_U;
  *ip++ = OP_SUBL_N_ESP_L;

  switch(argc) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
    *ip++ = 0x18;
    break;
  case 7:
  case 8:
    *ip++ = 0x28;
    break;
  }

  /* args */
  for (i = (4*argc - 4); i >= 0; i -= 4) {
    /* mov 0xN(%ebp),%eax */
    *ip++ = OP_MOVL_EAX_U;
    *ip++ = OP_MOVL_EAX_L;
    *ip++ = i + 8; 
    /* mov %eax,N(%esp) */
    *ip++ = OP_MOVL_ESP;
    if (i > 0) {
      *ip++ = 0x44;
      *ip++ = 0x24;
      *ip++ = i;
    }
    else {
      *ip++ = 0x04;
      *ip++ = 0x24;
    }
  }
  
  /* tracepoint */
  *ip++ = 0x90;
  *ip++ = 0x0f;
  *ip++ = 0x1f;
  *ip++ = 0x40;
  *ip++ = 0x00;

  /* ret */
  *ip++ = OP_LEAVE;
  *ip++ = OP_RET;

  /* allocate memory on a page boundary, for mprotect */
  probe->func = (void *)valloc(FUNC_SIZE);
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
    free(probe->func);
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

/*
 * Returns the address of the probe's generated code.
 */
VALUE dtraceprobe_addr(VALUE self)
{
  dtrace_probe_t *probe;
  
  Data_Get_Struct(self, dtrace_probe_t, probe);
  return INT2FIX(probe->func);
}

/*
 * Returns whether or not this probe is currently enabled, by invoking
 * the is-enabled tracepoint attached to the probe.
 */
VALUE dtraceprobe_is_enabled(VALUE self)
{
  dtrace_probe_t *probe;
  
  Data_Get_Struct(self, dtrace_probe_t, probe);
  return ((int)(*probe->func)()) ? Qtrue : Qfalse;
}

/*
 * Fires the probe, converting arguments based on the data provided -
 * no validation is done against the probe's declared types.
 */
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

/* 
 * Returns the offset for this probe in the PROFFS section, based on
 * the location of the DOF, and the location of this probe.
 */
VALUE dtraceprobe_probe_offset(VALUE self, VALUE file_addr, VALUE argc)
{
  void *probe_addr;
  int offset;
  probe_addr = (void *)FIX2INT(rb_funcall(self, rb_intern("addr"), 0));
  switch (FIX2INT(argc)) {
    case 0:
      offset = 40; /* 32 + 6 + 2 */
      break;
    case 1:
      offset = 46; /* 32 + 6 + 6 + 2 */
      break;
    default:
      offset = 46 + (FIX2INT(argc)-1) * 7; /* 32 + 6 + 6 + 7 per subsequent arg + 2 */
      break;
    }
  return INT2FIX((int)probe_addr - (int)FIX2INT(file_addr) + offset);
}

/* 
 * Returns the offset for this probe's is-enabled tracepoint in the
 * PRENOFFS section, based on the location of the DOF, and the
 * location of this probe.
 */
VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE file_addr)
{
  void *probe_addr;
  probe_addr = (void *)FIX2INT(rb_funcall(self, rb_intern("addr"), 0));
  return INT2FIX((int)probe_addr - (int)FIX2INT(file_addr) + 8);
}
