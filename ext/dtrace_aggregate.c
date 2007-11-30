/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE cDtraceProbe;
RUBY_EXTERN VALUE cDtraceRecDesc;

VALUE dtraceaggdata_init(VALUE self)
{
  dtrace_aggdata_t *aggdata;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);
  return self;
}

/*
 * Returns the description of this aggregate.
 */
VALUE dtraceaggdata_desc(VALUE self)
{
  VALUE string;
  dtrace_aggdata_t *aggdata;
  dtrace_aggdesc_t *aggdesc;
  dtrace_recdesc_t *nrec, *irec;  
  char *name, c[256];

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);

  aggdesc = aggdata->dtada_desc;
  nrec = &aggdesc->dtagd_rec[1];
  irec = &aggdesc->dtagd_rec[2];

  name = aggdata->dtada_data + nrec->dtrd_offset;
  string = rb_str_new2(name);
  return string;
}

/*
 * Returns the value of this aggregate.
 */
VALUE dtraceaggdata_value(VALUE self)
{
  dtrace_aggdata_t *aggdata;
  dtrace_aggdesc_t *aggdesc;
  dtrace_recdesc_t *nrec, *irec;  

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);

  aggdesc = aggdata->dtada_desc;
  nrec = &aggdesc->dtagd_rec[1];
  irec = &aggdesc->dtagd_rec[2];

  uint64_t n = *((uint64_t *)(aggdata->dtada_data + irec->dtrd_offset));

  return INT2FIX(n);
}

/*
 * Returns the size of this aggregate.
 */
VALUE dtraceaggdata_size(VALUE self)
{
  dtrace_aggdata_t *aggdata;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);

  return INT2FIX(aggdata->dtada_size);
}

/*
 * Yields each record for this aggregate.
 */
VALUE dtraceaggdata_each_record(VALUE self)
{
  VALUE dtracerecdesc;
  dtrace_aggdata_t *aggdata;
  dtrace_aggdesc_t *aggdesc;
  dtrace_recdesc_t *rec;
  int i;
  caddr_t data;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);
  aggdesc = aggdata->dtada_desc;

  for (i = 0; i < aggdesc->dtagd_nrecs; i++) {
    rec = &aggdesc->dtagd_rec[i]; 
    dtracerecdesc = Data_Wrap_Struct(cDtraceRecDesc, 0, NULL, rec);
    rb_iv_set(dtracerecdesc, "@aggdata", self);
    rb_yield(dtracerecdesc);
  }

  return Qnil;
} 

/*
 * Return the number of records in this aggregate.
 */
VALUE dtraceaggdata_num_records(VALUE self)
{
  VALUE dtracerecdesc;
  dtrace_aggdata_t *aggdata;
  dtrace_aggdesc_t *aggdesc;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);
  aggdesc = aggdata->dtada_desc;

  return INT2FIX(aggdesc->dtagd_nrecs);
} 

/* 
 * Access the array of records in this aggregate.
 */
VALUE dtraceaggdata_record(VALUE self, VALUE index)
{
  VALUE dtracerecdesc;
  dtrace_aggdata_t *aggdata;
  dtrace_aggdesc_t *aggdesc;
  dtrace_recdesc_t *rec;
  int i;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);
  aggdesc = aggdata->dtada_desc;

  i = FIX2INT(index);
  if (i >= aggdesc->dtagd_nrecs) 
    return Qnil;
  else {
    rec = &aggdesc->dtagd_rec[i]; 
    dtracerecdesc = Data_Wrap_Struct(cDtraceRecDesc, 0, NULL, rec);
    rb_iv_set(dtracerecdesc, "@aggdata", self);
    return dtracerecdesc;
  }
} 

/*
 * Return the probe associated with this aggregate.
 */
VALUE dtraceaggdata_probe(VALUE self)
{
  VALUE probe;
  dtrace_aggdata_t *aggdata;

  Data_Get_Struct(self, dtrace_aggdata_t, aggdata);
  probe = Data_Wrap_Struct(cDtraceProbe, 0, NULL, (dtrace_probedesc_t *)aggdata->dtada_pdesc);
  
  return probe;
}
