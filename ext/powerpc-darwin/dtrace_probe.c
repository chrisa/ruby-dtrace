/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 256
#define IS_ENABLED_FUNC_LEN 32

void install_insns(uint8_t *probe_insns, uint8_t *insns, int count)
{
  int i,j;
  uint8_t *ip;
  ip = insns;
  for (j = 1; j <= count; j++) {
    for (i = 0; i < 4; i++) {
      *ip++ = *probe_insns++;
    }
  }
}

/* :nodoc: */
VALUE dtraceprobe_init(VALUE self, VALUE rargc)
{
  dtrace_probe_t *probe;
  uint8_t *ip;
  int i;
  int argc = FIX2INT(rargc);
  uint8_t probe_insns[FUNC_SIZE];

  Data_Get_Struct(self, dtrace_probe_t, probe);

  /* First initialise the is_enabled tracepoint */
  uint8_t insns[FUNC_SIZE] = {
    /* stmw    r30,0xfff8(r1) */
    0xbf, 0xc1, 0xff, 0xf8, 
    /* stwu    r1,0xffd0(r1) */
    0x94, 0x21, 0xff, 0xd0, 
    /* or      r30,r1,r1 */
    0x7c, 0x3e, 0x0b, 0x78, 
    /* li      r0,0x0 */
    0x38, 0x00, 0x00, 0x00,
    /* or      r3,r0,r0 */
    0x7c, 0x03, 0x03, 0x78, 
    /* lwz     r1,0x0(r1) */
    0x80, 0x21, 0x00, 0x00, 
    /* lmw     r30,0xfff8(r1) */
    0xbb, 0xc1, 0xff, 0xf8, 
    /* blr */
    0x4e, 0x80, 0x00, 0x20
  };

  /* Now build probe tracepoint */
  switch (argc) {

  case 0:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
	/* stmw    r30,0xfff8(r1) */
	0xbf, 0xc1, 0xff, 0xf8, 
	/* stwu    r1,0xffd0(r1) */
	0x94, 0x21, 0xff, 0xd0, 
	/* or      r30,r1,r1 */
	0x7c, 0x3e, 0x0b, 0x78, 
	/* lwz     r1,0x0(r1) */
	0x80, 0x21, 0x00, 0x00,
	/* lmw     r30,0xfff8(r1) */
	0xbb, 0xc1, 0xff, 0xf8, 
	/* blr */
	0x4e, 0x80, 0x00, 0x20	
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 6);
    }
    break;

  case 1:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
	/* stmw    r30,0xfff8(r1) */
	0xbf, 0xc1, 0xff, 0xf8, 
	/* stwu    r1,0xffd0(r1) */
	0x94, 0x21, 0xff, 0xd0, 
	/* or      r30,r1,r1 */
	0x7c, 0x3e, 0x0b, 0x78,
	/* stw     r3,0x48(r30) */
	0x90, 0x7e, 0x00, 0x48, 
	/* lwz     r1,0x0(r1) */
	0x80, 0x21, 0x00, 0x00, 
	/* lmw     r30,0xfff8(r1) */
	0xbb, 0xc1, 0xff, 0xf8,
	/* blr */
	0x4e, 0x80, 0x00, 0x20
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 7);
    }
    break;

  case 2:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 12);
    }
    break;

  case 3:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 16);
    }
    break;

  case 4:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 16);
    }
    break;

  case 5:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 20);
    }
    break;

  case 6:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 24);
    }
    break;

  case 7:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 28);
    }
    break;

  case 8:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 32);
    }
    break;

  default:
    rb_raise(eDtraceException, "probe argc max is 8");
    return Qnil;
    break;
  }

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


/* 
 * Returns the offset for this probe in the PROFFS section, based on
 * the location of the DOF, and the location of this probe.
 */
VALUE dtraceprobe_probe_offset(VALUE self, VALUE file_addr, VALUE argc)
{
  void *probe_addr;
  int offset;
  probe_addr = (void *)FIX2INT(rb_funcall(self, rb_intern("addr"), 0));
  switch FIX2INT(argc) {
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
  return INT2FIX((int)probe_addr - (int)FIX2INT(file_addr) + 12);
}
