/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;
RUBY_EXTERN VALUE cDtraceProbe;

/* :nodoc: */
VALUE dtraceprobedata_init(VALUE self)
{
  dtrace_probedata_t *data;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  return self;
}

VALUE dtraceprobedata_probedesc(VALUE self)
{
  dtrace_probedata_t *data;
  dtrace_probedesc_t *pdp;
  VALUE probe;

  Data_Get_Struct(self, dtrace_probedata_t, data);

  pdp = data->dtpda_pdesc;
  probe = Data_Wrap_Struct(cDtraceProbe, 0, NULL, (dtrace_probedesc_t *)pdp);

  return probe;
}

static VALUE _handle_stack_record(const caddr_t addr, const dtrace_recdesc_t *rec)
{
  dtrace_actkind_t act;
  uint64_t *pc;
  pid_t pid = -1;
  int size; /* size of raw bytes not including trailing zeros */
  int i; /* index of last non-zero byte */
  VALUE raw;

  for (i = rec->dtrd_size - 1; (i >= 0) && !addr[i]; --i) {
  }
  size = (i + 1);

  raw = rb_ary_new();
  for (i = 0; i < size; i++)
    rb_ary_push(raw, INT2FIX(addr[i]));

  act = rec->dtrd_action;
  switch (act) {
  case DTRACEACT_STACK:
    break;
  case DTRACEACT_USTACK:
  case DTRACEACT_JSTACK:
    /* Get pid of user process */
    pc = (uint64_t *)(uintptr_t)addr;
    pid = (pid_t)*pc;
    break;
  default:
    rb_raise(eDtraceException, "Expected stack action, got %d\n", act);
  }

  return raw;
}

static int
_is_stack_action(dtrace_actkind_t act)
{
  int stack_action;
  switch (act) {
  case DTRACEACT_STACK:
  case DTRACEACT_USTACK:
  case DTRACEACT_JSTACK:
    stack_action = 1;
    break;
  default:
    stack_action = 0;
  }
  return (stack_action);
}

VALUE dtraceprobedata_each_record(VALUE self)
{
  dtrace_probedata_t *data;
  dtrace_eprobedesc_t *eprobe;
  dtrace_recdesc_t *rec;
  int i;
  VALUE dtracerecord;
  VALUE v;
  caddr_t addr;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  eprobe = data->dtpda_edesc;
  
  for (i = 0; i < eprobe->dtepd_nrecs; i++) {
    rec = &eprobe->dtepd_rec[i];
    if (rec->dtrd_size > 0) {
      addr = data->dtpda_data + rec->dtrd_offset;
	
      if (_is_stack_action(rec->dtrd_action)) {
	v = _handle_stack_record(addr, rec);
      }
      else {
	switch (rec->dtrd_size) {
	case 1:
	  v = INT2FIX((int)(*((uint8_t *)addr)));
	  break;
	case 2:
	  v = INT2FIX((int)(*((uint16_t *)addr)));
	  break;
	case 4:
	  v = INT2FIX(*((int32_t *)addr));
	  break;
	case 8:
	  v = INT2FIX(*((int64_t *)addr));
	  break;
	default:
	  v = handle_bytedata(addr, rec->dtrd_size);
	  break;
	}
      }
	
      dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("DtraceRecord"));
      rb_iv_set(dtracerecord, "@value", v);
      rb_yield(dtracerecord);
    }
  }
}
