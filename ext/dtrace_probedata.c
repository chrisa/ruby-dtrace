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

/*
 * Returns the enabled probe id which generated this data
 */
VALUE dtraceprobedata_epid(VALUE self)
{
  dtrace_probedata_t *data;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  return INT2FIX(data->dtpda_edesc->dtepd_epid);
}

/* 
 * Returns the DtraceProbe for the probe which generated this data 
 */
VALUE dtraceprobedata_probe(VALUE self)
{
  VALUE dtraceprobe;
  dtrace_probedata_t *data;
  dtrace_probedesc_t *pd;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  pd = data->dtpda_pdesc;

  if (pd) {
    dtraceprobe = Data_Wrap_Struct(cDtraceProbe, 0, NULL, (dtrace_probedesc_t *)pd);
    return dtraceprobe;
  }

  return Qnil;
}

/* Returns the CPU which generated this data */
VALUE dtraceprobedata_cpu(VALUE self)
{
  dtrace_probedata_t *data;
  processorid_t cpu;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  
  if (data) {
    cpu = data->dtpda_cpu;
    return INT2FIX(cpu);
  }
  else {
    return Qnil;
  }
}

/* Returns the indent level given to this data by DTrace */
VALUE dtraceprobedata_indent(VALUE self)
{
  dtrace_probedata_t *data;
  int indent;

  Data_Get_Struct(self, dtrace_probedata_t, data);

  if (data) {
    indent = data->dtpda_indent;
    return INT2FIX(indent / 2);
  }
  else {
    return Qnil;
  }
}

/* Returns the prefix given to this data by DTrace */
VALUE dtraceprobedata_prefix(VALUE self)
{
  dtrace_probedata_t *data;
  const char *prefix;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  prefix = data->dtpda_prefix;

  if (prefix) 
    return rb_str_new2(prefix);
  else
    return Qnil;
}

/* Returns the flow kind given to this data by DTrace */
VALUE dtraceprobedata_flow(VALUE self)
{
  dtrace_probedata_t *data;

  Data_Get_Struct(self, dtrace_probedata_t, data);

  switch (data->dtpda_flow) {
  case DTRACEFLOW_ENTRY:
    return rb_str_new2("->");
    break;
  case DTRACEFLOW_RETURN:
    return rb_str_new2("<-");
    break;
  default:
    return Qnil;
  }
}

/* 
 * Yields each record in this DtraceProbedata in turn. Records are
 * yielded as either DtraceRecords or DtraceStackRecords as
 * appropriate for the type of action.
 */
VALUE dtraceprobedata_each_record(VALUE self)
{
  dtrace_probedata_t *data;
  dtrace_eprobedesc_t *eprobe;
  dtrace_recdesc_t *rec;
  dtrace_hdl_t *handle;
  dtrace_actkind_t act;
  int i;
  caddr_t addr;
  VALUE dtracerecord;
  VALUE dtracehandle;
  VALUE v;

  Data_Get_Struct(self, dtrace_probedata_t, data);
  dtracehandle = rb_iv_get(self, "@handle");
  Data_Get_Struct(dtracehandle, dtrace_hdl_t, handle);

  eprobe = data->dtpda_edesc;
  
  for (i = 0; i < eprobe->dtepd_nrecs; i++) {
    v = 0;
    rec = &eprobe->dtepd_rec[i];
    if (rec->dtrd_size > 0) {
      act = rec->dtrd_action;
      addr = data->dtpda_data + rec->dtrd_offset;
      
      switch (act) {
      case DTRACEACT_STACK:
      case DTRACEACT_USTACK:
      case DTRACEACT_JSTACK:
	/* Stack records come from bufdata */
	/* v = _handle_stack_record(handle, addr, rec); */
	/* v = _handle_ustack_record(handle, addr, rec); */
	break;
      case DTRACEACT_PRINTA:
	/* don't want the probedata record for a printa() action */
	break;
      default:
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
	
      if (v) {
	dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("DtraceRecord"));
	rb_iv_set(dtracerecord, "@value", v);
	rb_iv_set(dtracerecord, "@from", rb_str_new2("probedata"));
	rb_iv_set(dtracerecord, "@index", INT2FIX(i));
	rb_iv_set(dtracerecord, "@action", INT2FIX(act));
	rb_yield(dtracerecord);
      }
    }
  }
}
