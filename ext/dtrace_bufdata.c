/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDTraceException;
RUBY_EXTERN VALUE cDTraceAggData;
RUBY_EXTERN VALUE cDTraceRecDesc;
RUBY_EXTERN VALUE cDTraceProbe;

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
 * Returns the DTraceProbe for the probe which generated this data
 */
VALUE dtracebufdata_probe(VALUE self)
{
  dtrace_bufdata_t *bufdata;
  VALUE dtraceprobe;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);

  if (bufdata->dtbda_probe) {
    dtraceprobe = Data_Wrap_Struct(cDTraceProbe, 0, NULL, (dtrace_probedesc_t *)bufdata->dtbda_probe->dtpda_pdesc);
    return dtraceprobe;
  }

  return Qnil;
}

/*
 * Returns the record in this DTraceBufdata. Records are returned as
 * either DTraceRecords or DTraceStackRecords as appropriate for the
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
    dtraceaggdata = Data_Wrap_Struct(cDTraceAggData, 0, NULL, (dtrace_bufdata_t *)bufdata);
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
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("DTrace::PrintfRecord"));
    rb_iv_set(dtracerecord, "@from", rb_str_new2("bufdata"));
    rb_iv_set(dtracerecord, "@value", v);
    return (dtracerecord);
    break;
  case DTRACEACT_STACK:
  case DTRACEACT_USTACK:
  case DTRACEACT_JSTACK:
    /* stand-alone stack(), ustack(), or jstack() action */
    v = rb_str_new2(s);
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("DTrace::StackRecord"));
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
    dtracerecord = rb_class_new_instance(0, NULL, rb_path2class("DTrace::Record"));
    rb_iv_set(dtracerecord, "@value", v);
    rb_iv_set(dtracerecord, "@action", INT2FIX(act));
    rb_iv_set(dtracerecord, "@from", rb_str_new2("bufdata"));
    return (dtracerecord);
  }
  else {
    return Qnil;
  }
}
