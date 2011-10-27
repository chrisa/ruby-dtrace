/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;

/* :nodoc: */
VALUE dtraceaggdata_init(VALUE self)
{
  dtrace_bufdata_t *data;

  Data_Get_Struct(self, dtrace_bufdata_t, data);
  return self;
}

/* Returns the value of this aggregate, be it the aggregation value,
   or a member of an aggregation key tuple. */
VALUE dtraceaggdata_value(VALUE self)
{
  dtrace_bufdata_t *bufdata;
  const dtrace_aggdata_t *aggdata;
  const dtrace_aggdesc_t *aggdesc;
  const dtrace_recdesc_t *rec;
  const char *s;
  dtrace_actkind_t act = DTRACEACT_NONE;
  int64_t aggid;
  uint64_t normal;
  caddr_t addr;
  int64_t value;
  VALUE v = Qnil;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);
  aggdata = bufdata->dtbda_aggdata;
  s = bufdata->dtbda_buffered;
  rec = bufdata->dtbda_recdesc;

  if (aggdata == NULL) {
    rb_raise(eDtraceException, "null aggdata");
    return Qnil;
  }

  aggdesc = aggdata->dtada_desc;

  if (aggdesc == NULL) {
    rb_raise(eDtraceException, "null aggdesc");
    return Qnil;
  }

  aggid = *((int64_t *)(aggdata->dtada_data +
			aggdesc->dtagd_rec[0].dtrd_offset));
  if (aggid < 0) {
    rb_raise(eDtraceException, "negative aggregation ID");
    return Qnil;
  }

  act = rec->dtrd_action;

  if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGKEY) {

    switch (act) {
    case DTRACEACT_STACK:
    case DTRACEACT_USTACK:
    case DTRACEACT_JSTACK:
      /* todo */
      break;
    case DTRACEACT_USYM:
    case DTRACEACT_UADDR:
    case DTRACEACT_UMOD:
    case DTRACEACT_SYM:
    case DTRACEACT_MOD:
      /* todo */
      break;
    default:
      v = handle_bytedata((aggdata->dtada_data + rec->dtrd_offset), rec->dtrd_size);
    }


  } else if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGVAL) {

    normal = aggdata->dtada_normal;
    addr = aggdata->dtada_data + rec->dtrd_offset;

    if (act == DTRACEAGG_AVG) {
      uint64_t *data = (uint64_t *)addr;
      value = (data[0] ? (long long)(data[1] / normal / data[0]) : 0);
    } else {
      value = (*((int64_t *)addr)) / normal;
    }

    if (act == DTRACEAGG_QUANTIZE || act == DTRACEAGG_LQUANTIZE) {
      v = Qnil; // dtj_new_distribution(data, rec, jc);
    } else {
      switch (act) {
      case DTRACEAGG_COUNT:
	if (value < 0)
	  rb_raise(eDtraceException, "count value is negative");
	v = LL2NUM(value);
	break;
      case DTRACEAGG_AVG:
      case DTRACEAGG_MIN:
      case DTRACEAGG_MAX:
      case DTRACEAGG_SUM:
	v = LL2NUM(value);
	break;
      default:
	v = Qnil;
	rb_raise(eDtraceException, "unexpected aggregation action: %d", act);
      }
    }

  } else if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGVAL) {

    v = Qnil;

  }

  return v;
}

/* Return the type of this DtraceAggData: tuple, value or last. Used
   to form tuples and values into DtraceAggregate objects. */
VALUE dtraceaggdata_aggtype(VALUE self)
{
  dtrace_bufdata_t *bufdata;
  VALUE v;

  Data_Get_Struct(self, dtrace_bufdata_t, bufdata);

  if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGKEY)
    v = rb_str_new2("tuple");
  else if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGVAL)
    v = rb_str_new2("value");
  else if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGLAST)
    v = rb_str_new2("last");
  else
    v = rb_str_new2("unknown");

  return v;
}

