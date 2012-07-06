/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;
RUBY_EXTERN VALUE cDtraceAggData;
RUBY_EXTERN VALUE cDtraceRecDesc;
RUBY_EXTERN VALUE cDtraceProbe;

/* :nodoc: */
VALUE dtracebufdata_init(VALUE self)
{
  dtrace_bufdata_t *data;

  Data_Get_Struct(self, dtrace_bufdata_t, data);
  return self;
}

/*
 * Returns the enabled probe id which generated this data
 */
VALUE dtracebufdata_epid(VALUE self)
{
  dtrace_bufdata_t *bufdata;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);

  if (bufdata->dtbda_probe) {
    return INT2FIX(bufdata->dtbda_probe->dtpda_edesc->dtepd_epid);
  }

  return Qnil;
}


/*
 * Returns the DtraceProbe for the probe which generated this data
 */
VALUE dtracebufdata_probe(VALUE self)
{
  dtrace_bufdata_t *bufdata;
  VALUE dtraceprobe;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);

  if (bufdata->dtbda_probe) {
    dtraceprobe = Data_Wrap_Struct(cDtraceProbe, 0, NULL, (dtrace_probedesc_t *)bufdata->dtbda_probe->dtpda_pdesc);
    return dtraceprobe;
  }

  return Qnil;
}

/*
 * Returns the record in this DtraceBufdata. Records are returned as
 * either DtraceRecords or DtraceStackRecords as appropriate for the
 * type of action.
 */
VALUE dtracebufdata_record(VALUE self)
{
  dtrace_bufdata_t *bufdata;
  const dtrace_recdesc_t *rec;
  dtrace_actkind_t act = DTRACEACT_NONE;
  const char *s;
  VALUE v = Qnil;
  VALUE dtracerecord;
  VALUE dtraceaggdata;
  VALUE dtracerecdesc;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);

  if (bufdata->dtbda_aggdata) {
    dtraceaggdata = Data_Wrap_Struct(cDtraceAggData, 0, NULL, (dtrace_bufdata_t *)bufdata);
    return dtraceaggdata;
  }

  s = bufdata->dtbda_buffered;
  if (s == NULL) {
    return Qnil;
  }

  rec = bufdata->dtbda_recdesc;
  if (rec) {
    act = rec->dtrd_action;
  }

  switch (act) {
  case DTRACEACT_DIFEXPR:
    /* trace() action */
    break;
  case DTRACEACT_PRINTF:
    /* printf action, not available in probedata */
    v = rb_str_new2(s);
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("Dtrace::PrintfRecord"));
    rb_iv_set(dtracerecord, "@from", rb_str_new2("bufdata"));
    rb_iv_set(dtracerecord, "@value", v);
    return (dtracerecord);
    break;
  case DTRACEACT_STACK:
  case DTRACEACT_USTACK:
  case DTRACEACT_JSTACK:
    /* stand-alone stack(), ustack(), or jstack() action */
    v = rb_str_new2(s);
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("Dtrace::StackRecord"));
    rb_iv_set(dtracerecord, "@from", rb_str_new2("bufdata"));
    rb_funcall(dtracerecord, rb_intern("parse"), 1, v);
    return (dtracerecord);
    break;
  case DTRACEACT_USYM:
  case DTRACEACT_UADDR:
  case DTRACEACT_UMOD:
  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
    v = rb_str_new2(s);
    break;
  case DTRACEACT_PRINTA:
    v = rb_str_new2(s);
    break;
  default:
    /*
     * The record handle defers nothing else to this
     * bufhandler.
     */
    break;
  }

  if (!NIL_P(v)) {
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("Dtrace::Record"));
    rb_iv_set(dtracerecord, "@value", v);
    rb_iv_set(dtracerecord, "@action", INT2FIX(act));
    rb_iv_set(dtracerecord, "@from", rb_str_new2("bufdata"));
    return (dtracerecord);
  }
  else {
    return Qnil;
  }
}
