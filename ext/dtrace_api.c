/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

VALUE cDtrace;
VALUE cDtraceProbe;
VALUE cDtraceProgram;
VALUE cDtraceProgramInfo;
VALUE cDtraceAggData;
VALUE cDtraceRecDesc;

VALUE eDtraceException;

void Init_dtrace_api() {

  cDtrace = rb_define_class("Dtrace",          rb_cObject);
  rb_define_method(cDtrace, "initialize",      dtrace_init,                0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "each_probe",      dtrace_each_probe,          0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "compile",         dtrace_strcompile,         -1); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "stop",            dtrace_hdl_stop,            0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "status",          dtrace_hdl_status,          0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "go",              dtrace_hdl_go,              0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "each_aggregate",  dtrace_hdl_each_aggregate,  0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "aggregate_print", dtrace_hdl_aggregate_print, 0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "aggregate_snap",  dtrace_hdl_aggregate_snap,  0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "aggregate_clear", dtrace_hdl_aggregate_clear, 0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "error",           dtrace_hdl_error,           0); // in: dtrace_hdl.c
  rb_define_method(cDtrace, "setopt",          dtrace_hdl_setopt,          2); // in: dtrace_hdl.c
  rb_define_alloc_func(cDtrace, dtrace_hdl_alloc);

  cDtraceProbe = rb_define_class("DtraceProbe", rb_cObject);
  rb_define_method(cDtraceProbe, "initialize", dtraceprobe_init,     0); // in: dtrace_probe.c
  rb_define_method(cDtraceProbe, "probe_id",   dtraceprobe_probe_id, 0); // in: dtrace_probe.c
  rb_define_method(cDtraceProbe, "provider",   dtraceprobe_provider, 0); // in: dtrace_probe.c
  rb_define_method(cDtraceProbe, "mod",        dtraceprobe_mod,      0); // in: dtrace_probe.c
  rb_define_method(cDtraceProbe, "func",       dtraceprobe_func,     0); // in: dtrace_probe.c
  rb_define_method(cDtraceProbe, "name",       dtraceprobe_name,     0); // in: dtrace_probe.c

  cDtraceProgram = rb_define_class("DtraceProgram", rb_cObject);
  rb_define_method(cDtraceProgram, "initialize",         dtraceprogram_init, 0); // in: dtrace_program.c
  rb_define_method(cDtraceProgram, "execute",            dtraceprogram_exec, 0); // in: dtrace_program.c
  rb_define_method(cDtraceProgram, "info",               dtraceprogram_info, 0); // in: dtrace_program.c

  cDtraceProgramInfo = rb_define_class("DtraceProgramInfo", rb_cObject);
  rb_define_method(cDtraceProgramInfo, "initialize",         dtraceprograminfo_init,               0); // in: dtrace_programinfo.c 
  rb_define_method(cDtraceProgramInfo, "aggregates_count",   dtraceprograminfo_aggregates_count,   0); // in: dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "recgens_count",      dtraceprograminfo_recgens_count,      0); // in: dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "matches_count",      dtraceprograminfo_matches_count,      0); // in: dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "speculations_count", dtraceprograminfo_speculations_count, 0); // in: dtrace_programinfo.c

  cDtraceAggData = rb_define_class("DtraceAggData", rb_cObject);
  rb_define_method(cDtraceAggData, "initialize",         dtraceaggdata_init,        0); // in: dtrace_aggregate.c 
  rb_define_method(cDtraceAggData, "desc",               dtraceaggdata_desc,        0); // in: dtrace_aggregate.c 
  rb_define_method(cDtraceAggData, "value",              dtraceaggdata_value,       0); // in: dtrace_aggregate.c 
  rb_define_method(cDtraceAggData, "size",               dtraceaggdata_size,        0); // in: dtrace_aggregate.c 
  rb_define_method(cDtraceAggData, "each_record",        dtraceaggdata_each_record, 0); // in: dtrace_aggregate.c 
  rb_define_method(cDtraceAggData, "num_records",        dtraceaggdata_num_records, 0); // in: dtrace_aggregate.c
  rb_define_method(cDtraceAggData, "[]",                 dtraceaggdata_record,      1); // in: dtrace_aggregate.c
  rb_define_method(cDtraceAggData, "probe",              dtraceaggdata_probe,       0); // in: dtrace_aggregate.c

  cDtraceRecDesc = rb_define_class("DtraceRecDesc", rb_cObject);
  rb_define_method(cDtraceRecDesc, "initialize",         dtracerecdesc_init, 0); // in: dtrace_recdesc.c 
  rb_define_method(cDtraceRecDesc, "data",               dtracerecdesc_data, 0); // in: dtrace_recdesc.c   

  eDtraceException = rb_define_class("DtraceException", rb_eStandardError);
}

