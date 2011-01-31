/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

RUBY_EXTERN VALUE eDtraceException;

#define ARGC_MAX 6
#define FUNC_SIZE 256
#define IS_ENABLED_FUNC_LEN 8

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
    0x48, 0x33, 0xc0, 0xc3,
    0x90, 0x00, 0x00, 0x00
  };

  if (argc <= ARGC_MAX) {
    {
      uint8_t probe_insns[FUNC_SIZE] = {
	0xc3, 0x90, 0x90, 0x90,
	0x90, 0x00, 0x00, 0x00
      };
      install_insns(probe_insns, &insns[IS_ENABLED_FUNC_LEN], 2);
    }
  }
  else {
    rb_raise(eDtraceException, "probe argc max is %d", ARGC_MAX);
    return Qnil;
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

VALUE dtraceprobe_addr(VALUE self)
{
  dtrace_probe_t *probe;
  
  Data_Get_Struct(self, dtrace_probe_t, probe);
  return LL2NUM((uint64_t)(probe->func));
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
  void *argv[ARGC_MAX]; // probe argc max for now.
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
  (void)(*func)(argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
  
  return Qnil;
}

VALUE dtraceprobe_probe_offset(VALUE self, VALUE rfile, VALUE argc)
{
  return INT2FIX(IS_ENABLED_FUNC_LEN);
}

VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE rfile)
{
  return INT2FIX(1);
}
