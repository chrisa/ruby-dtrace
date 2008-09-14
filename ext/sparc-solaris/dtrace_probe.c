/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define FUNC_SIZE 256
#define IS_ENABLED_FUNC_LEN 48

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
    /* save        %sp, -104, %sp */
    0x9d, 0xe3, 0xbf, 0x98, 
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
  };

  /* Now build probe tracepoint */
  switch (argc) {

  case 0:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0x90, 
        /* nop */
        0x01, 0x00, 0x00, 0x00,   
        /* nop */
        0x01, 0x00, 0x00, 0x00,   
        /* ret */
        0x81, 0xc7, 0xe0, 0x08, 
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 8);
    }
    break;

  case 1:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0, 
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* nop */
        0x01, 0x00, 0x00, 0x00,   
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 12);
    }
    break;

  case 2:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 12);
    }
    break;

  case 3:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 16);
    }
    break;

  case 4:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* st          %i3, [%fp + 80] */
        0xf6, 0x27, 0xa0, 0x50,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* ld          [%fp + 80], %l3 */
        0xe6, 0x07, 0xa0, 0x50,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* or          %l3, %g0, %o3 */
        0x96, 0x14, 0x00, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 16);
    }
    break;

  case 5:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* st          %i3, [%fp + 80] */
        0xf6, 0x27, 0xa0, 0x50,
        /* st          %i4, [%fp + 84] */
        0xf8, 0x27, 0xa0, 0x54,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* ld          [%fp + 80], %l3 */
        0xe6, 0x07, 0xa0, 0x50,
        /* ld          [%fp + 84], %l4 */
        0xe8, 0x07, 0xa0, 0x54,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* or          %l3, %g0, %o3 */
        0x96, 0x14, 0xc0, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* or          %l4, %g0, %o4 */
        0x98, 0x15, 0x00, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 20);
    }
    break;

  case 6:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* st          %i3, [%fp + 80] */
        0xf6, 0x27, 0xa0, 0x50,
        /* st          %i4, [%fp + 84] */
        0xf8, 0x27, 0xa0, 0x54,
        /* st          %i5, [%fp + 88] */
        0xfa, 0x27, 0xa0, 0x58,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* ld          [%fp + 80], %l3 */
        0xe6, 0x07, 0xa0, 0x50,
        /* ld          [%fp + 84], %l5 */
        0xea, 0x07, 0xa0, 0x54,
        /* ld          [%fp + 88], %l4 */
        0xe8, 0x07, 0xa0, 0x58,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* or          %l3, %g0, %o3 */
        0x96, 0x14, 0xc0, 0x00,
        /* or          %l5, %g0, %o4 */
        0x98, 0x15, 0x40, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* or          %l4, %g0, %o5 */
        0x9a, 0x15, 0x00, 0x00,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 24);
    }
    break;

  case 7:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0xa0,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* st          %i3, [%fp + 80] */
        0xf6, 0x27, 0xa0, 0x50,
        /* st          %i4, [%fp + 84] */
        0xf8, 0x27, 0xa0, 0x54,
        /* st          %i5, [%fp + 88] */
        0xfa, 0x27, 0xa0, 0x58,
        /* ld          [%fp + 92], %l0 */
        0xe0, 0x07, 0xa0, 0x5c,
        /* st          %l0, [%fp + 92] */
        0xe0, 0x27, 0xa0, 0x5c,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* ld          [%fp + 80], %l3 */
        0xe6, 0x07, 0xa0, 0x50,
        /* ld          [%fp + 84], %l5 */
        0xea, 0x07, 0xa0, 0x54,
        /* ld          [%fp + 88], %l4 */
        0xec, 0x07, 0xa0, 0x58,
        /* ld          [%fp + 92], %l5 */
        0xe8, 0x07, 0xa0, 0x5c,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* or          %l3, %g0, %o3 */
        0x96, 0x14, 0xc0, 0x00,
        /* or          %l5, %g0, %o4 */
        0x98, 0x15, 0x40, 0x00,
        /* or          %l6, %g0, %o5 */
        0x9a, 0x15, 0x80, 0x00,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* st          %l4, [%sp + 92] */
        0xe8, 0x23, 0xa0, 0x5c,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 28);
    }
    break;

  case 8:
    {
      uint8_t probe_insns[FUNC_SIZE] = {
        /* save        %sp, -96, %sp */
        0x9d, 0xe3, 0xbf, 0x98,
        /* st          %i0, [%fp + 68] */
        0xf0, 0x27, 0xa0, 0x44,
        /* st          %i1, [%fp + 72] */
        0xf2, 0x27, 0xa0, 0x48 ,
        /* st          %i2, [%fp + 76] */
        0xf4, 0x27, 0xa0, 0x4c,
        /* st          %i3, [%fp + 80] */
        0xf6, 0x27, 0xa0, 0x50,
        /* st          %i4, [%fp + 84] */
        0xf8, 0x27, 0xa0, 0x54,
        /* st          %i5, [%fp + 88] */
        0xfa, 0x27, 0xa0, 0x58,
        /* ld          [%fp + 92], %l0 */
        0xe0, 0x07, 0xa0, 0x5c,
        /* st          %l0, [%fp + 92] */
        0xe0, 0x27, 0xa0, 0x5c,
        /* ld          [%fp + 96], %l0 */
        0xe0, 0x07, 0xa0, 0x60,
        /* st          %l0, [%fp + 96] */
        0xe0, 0x27, 0xa0, 0x60,
        /* ld          [%fp + 68], %l0 */
        0xe0, 0x07, 0xa0, 0x44,
        /* ld          [%fp + 72], %l1 */
        0xe2, 0x07, 0xa0, 0x48,
        /* ld          [%fp + 76], %l2 */
        0xe4, 0x07, 0xa0, 0x4c,
        /* ld          [%fp + 80], %l3 */
        0xe6, 0x07, 0xa0, 0x50,
        /* ld          [%fp + 84], %l5 */
        0xea, 0x07, 0xa0, 0x54,
        /* ld          [%fp + 88], %l6 */
        0xec, 0x07, 0xa0, 0x58,
        /* ld          [%fp + 92], %l7 */
        0xee, 0x07, 0xa0, 0x5c,
        /* ld          [%fp + 96], %l4 */
        0xe8, 0x07, 0xa0, 0x60,
        /* or          %l0, %g0, %o0 */
        0x90, 0x14, 0x00, 0x00,
        /* or          %l1, %g0, %o1 */
        0x92, 0x14, 0x40, 0x00,
        /* or          %l2, %g0, %o2 */
        0x94, 0x14, 0x80, 0x00,
        /* or          %l3, %g0, %o3 */
        0x96, 0x14, 0xc0, 0x00,
        /* or          %l5, %g0, %o4 */
        0x98, 0x15, 0x40, 0x00,
        /* or          %l6, %g0, %o5 */
        0x9a, 0x15, 0x80, 0x00,
        /* st          %l7, [%sp + 92] */
        0xee, 0x23, 0xa0, 0x5c,
        /* nop */
        0x01, 0x00, 0x00, 0x00,
        /* st          %l4, [%sp + 96] */
        0xe8, 0x23, 0xa0, 0x60,
        /* ret */
        0x81, 0xc7, 0xe0, 0x08,
        /* restore */
        0x81, 0xe8, 0x00, 0x00,      
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
   * 48 bytes - length of is_enabled function
   * +
   * 3 instrs function entry - 12 bytes
   * +
   * 3 instrs per argument - 12 bytes
   *
   */
  return INT2FIX(IS_ENABLED_FUNC_LEN + 12 + (FIX2INT(argc) * 12));
}

VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE rfile)
{
  return INT2FIX(8);
}
