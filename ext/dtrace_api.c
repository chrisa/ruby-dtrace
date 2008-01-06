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
VALUE cDtraceProbeData;
VALUE cDtraceBufData;
VALUE cDtraceProcess;

VALUE eDtraceException;

void Init_dtrace_api() {

  cDtrace = rb_define_class("Dtrace",          rb_cObject);
  rb_define_method(cDtrace, "initialize",      dtrace_init,                0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "each_probe",      dtrace_each_probe,          0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "compile",         dtrace_strcompile,         -1); // in dtrace_hdl.c
  rb_define_method(cDtrace, "stop",            dtrace_hdl_stop,            0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "status",          dtrace_hdl_status,          0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "go",              dtrace_hdl_go,              0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "error",           dtrace_hdl_error,           0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "setopt",          dtrace_hdl_setopt,          2); // in dtrace_hdl.c
  rb_define_method(cDtrace, "sleep",           dtrace_hdl_sleep,           0); // in dtrace_hdl.c
  rb_define_method(cDtrace, "work",            dtrace_hdl_work,           -1); // in dtrace_hdl.c
  rb_define_method(cDtrace, "buf_consumer",    dtrace_hdl_buf_consumer,    1); // in dtrace_hdl.c
  rb_define_method(cDtrace, "createprocess",   dtrace_hdl_createprocess,   1); // in dtrace_hdl.c
  rb_define_method(cDtrace, "grabprocess",     dtrace_hdl_grabprocess,     1); // in dtrace_hdl.c
  rb_define_alloc_func(cDtrace, dtrace_hdl_alloc);

  cDtraceProcess = rb_define_class("DtraceProcess", rb_cObject);
  rb_define_method(cDtraceProcess, "initialize",    dtrace_process_init,     0); // in dtrace_process.c
  rb_define_method(cDtraceProcess, "continue",      dtrace_process_continue, 0); // in dtrace_process.c

  cDtraceProbe = rb_define_class("DtraceProbe", rb_cObject);
  rb_define_method(cDtraceProbe, "initialize", dtraceprobe_init,     0); // in dtrace_probe.c
  rb_define_method(cDtraceProbe, "probe_id",   dtraceprobe_probe_id, 0); // in dtrace_probe.c
  rb_define_method(cDtraceProbe, "provider",   dtraceprobe_provider, 0); // in dtrace_probe.c
  rb_define_method(cDtraceProbe, "mod",        dtraceprobe_mod,      0); // in dtrace_probe.c
  rb_define_method(cDtraceProbe, "func",       dtraceprobe_func,     0); // in dtrace_probe.c
  rb_define_method(cDtraceProbe, "name",       dtraceprobe_name,     0); // in dtrace_probe.c

  cDtraceProbeData = rb_define_class("DtraceProbeData", rb_cObject);
  rb_define_method(cDtraceProbeData, "initialize",  dtraceprobedata_init,        0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "epid",        dtraceprobedata_epid,        0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "probe",       dtraceprobedata_probe,       0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "cpu",         dtraceprobedata_cpu,         0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "indent",      dtraceprobedata_indent,      0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "prefix",      dtraceprobedata_prefix,      0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "flow",        dtraceprobedata_flow,        0); // in dtrace_probedata.c
  rb_define_method(cDtraceProbeData, "each_record", dtraceprobedata_each_record, 0); // in dtrace_probedata.c

  cDtraceBufData = rb_define_class("DtraceBufData", rb_cObject);
  rb_define_method(cDtraceBufData, "initialize",  dtracebufdata_init,   0); // in dtrace_bufdata.c
  rb_define_method(cDtraceBufData, "epid",        dtracebufdata_epid,   0); // in dtrace_bufdata.c
  rb_define_method(cDtraceBufData, "probe",       dtracebufdata_probe,  0); // in dtrace_bufdata.c
  rb_define_method(cDtraceBufData, "record",      dtracebufdata_record, 0); // in dtrace_bufdata.c

  cDtraceProgram = rb_define_class("DtraceProgram", rb_cObject);
  rb_define_method(cDtraceProgram, "initialize",         dtraceprogram_init, 0); // in dtrace_program.c
  rb_define_method(cDtraceProgram, "execute",            dtraceprogram_exec, 0); // in dtrace_program.c
  rb_define_method(cDtraceProgram, "info",               dtraceprogram_info, 0); // in dtrace_program.c

  cDtraceProgramInfo = rb_define_class("DtraceProgramInfo", rb_cObject);
  rb_define_method(cDtraceProgramInfo, "initialize",         dtraceprograminfo_init,               0); // in dtrace_programinfo.c 
  rb_define_method(cDtraceProgramInfo, "aggregates_count",   dtraceprograminfo_aggregates_count,   0); // in dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "recgens_count",      dtraceprograminfo_recgens_count,      0); // in dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "matches_count",      dtraceprograminfo_matches_count,      0); // in dtrace_programinfo.c
  rb_define_method(cDtraceProgramInfo, "speculations_count", dtraceprograminfo_speculations_count, 0); // in dtrace_programinfo.c

  cDtraceAggData = rb_define_class("DtraceAggData", rb_cObject);
  rb_define_method(cDtraceAggData, "initialize",         dtraceaggdata_init,    0); // in dtrace_aggdata.c 
  rb_define_method(cDtraceAggData, "value",              dtraceaggdata_value,   0); // in dtrace_aggdata.c
  rb_define_method(cDtraceAggData, "aggtype",            dtraceaggdata_aggtype, 0); // in dtrace_aggdata.c

  cDtraceRecDesc = rb_define_class("DtraceRecDesc", rb_cObject);
  rb_define_method(cDtraceRecDesc, "initialize",         dtracerecdesc_init, 0); // in dtrace_recdesc.c 

  eDtraceException = rb_define_class("DtraceException", rb_eStandardError);
}

