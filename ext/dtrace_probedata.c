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

static VALUE _handle_ustack_record(dtrace_hdl_t *handle, caddr_t addr, const dtrace_recdesc_t *rec)
{
  VALUE stack;
  stack = rb_ary_new();

  /* TODO, apple and solaris ustack */
  return stack;
}

static VALUE _handle_stack_record(dtrace_hdl_t *handle, caddr_t addr, const dtrace_recdesc_t *rec)
{
  VALUE stack = Qnil;
  int size, i;
  int depth;
  uint64_t pc;
  dtrace_syminfo_t dts;
  char c[PATH_MAX * 2];

#ifdef __APPLE__
  __GElf_Sym sym;
#else
  GElf_Sym sym;
#endif

  size = rec->dtrd_size / rec->dtrd_arg;
  depth = rec->dtrd_arg;

  stack = rb_ary_new();

  for (i = 0; i < depth; i++) {
    
    switch (size) {
    case sizeof (uint32_t):
      pc = *((uint32_t *)addr);
      break;

    case sizeof (uint64_t):
      pc = *((uint64_t *)addr);
      break;

    default:
      rb_raise(eDtraceException, "bad stack pc");
      return Qnil;
    }

    if (pc == (uint64_t)NULL)
      break;

    addr += size;

    if (dtrace_lookup_by_addr(handle, pc, &sym, &dts) == 0) {
      if (pc > sym.st_value) {
	(void) snprintf(c, sizeof (c), "%s`%s+0x%llx",
			dts.dts_object, dts.dts_name,
			pc - sym.st_value);
      }
      else {
	(void) snprintf(c, sizeof (c), "%s`%s",
			dts.dts_object, dts.dts_name);
      }
    } 
    else {
      if (dtrace_lookup_by_addr(handle, pc, NULL, &dts) == 0) {
	(void) snprintf(c, sizeof (c), "%s`0x%llx",
			dts.dts_object, pc);
      }
      else {
	(void) snprintf(c, sizeof (c), "0x%llx", pc);
      }
    }

    rb_ary_push(stack, rb_str_new2(c));
  }

  return stack;
}

VALUE dtraceprobedata_each_record(VALUE self)
{
  dtrace_probedata_t *data;
  dtrace_eprobedesc_t *eprobe;
  dtrace_recdesc_t *rec;
  dtrace_hdl_t *handle;
  dtrace_actkind_t act;
  int i;
  VALUE dtracerecord;
  VALUE dtracehandle;
  VALUE v;
  caddr_t addr;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  dtracehandle = rb_iv_get(self, "@handle");
  Data_Get_Struct(dtracehandle, dtrace_hdl_t, handle);

  eprobe = data->dtpda_edesc;
  
  for (i = 0; i < eprobe->dtepd_nrecs; i++) {
    rec = &eprobe->dtepd_rec[i];
    if (rec->dtrd_size > 0) {
      act = rec->dtrd_action;
      addr = data->dtpda_data + rec->dtrd_offset;
	
      if (act == DTRACEACT_STACK) {
	v = _handle_stack_record(handle, addr, rec);
      }
      else if (act == DTRACEACT_USTACK || act == DTRACEACT_JSTACK) {
	v = _handle_ustack_record(handle, addr, rec);
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
