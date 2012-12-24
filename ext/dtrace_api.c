/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

VALUE cDTrace;
VALUE cDTraceProbeDesc;
VALUE cDTraceProgram;
VALUE cDTraceProgramInfo;
VALUE cDTraceAggData;
VALUE cDTraceRecDesc;
VALUE cDTraceProbeData;
VALUE cDTraceBufData;
VALUE cDTraceProcess;
VALUE cDTraceDropData;
VALUE cDTraceErrData;
VALUE cDTraceProbe;

VALUE eDTraceException;

void Init_dtrace_api() {

  cDTrace = rb_define_class("DTrace", rb_cObject);
  rb_define_method(cDTrace, "close", dtrace_hdl_close, 0);
  rb_define_method(cDTrace, "each_probe_all", dtrace_each_probe_all, 0);
  rb_define_method(cDTrace, "each_probe_match", dtrace_each_probe_match, 4);
  rb_define_method(cDTrace, "each_probe_prog", dtrace_each_probe_prog, 1);
  rb_define_method(cDTrace, "compile", dtrace_strcompile, -1);
  rb_define_method(cDTrace, "stop", dtrace_hdl_stop, 0);
  rb_define_method(cDTrace, "status", dtrace_hdl_status, 0);
  rb_define_method(cDTrace, "go", dtrace_hdl_go, 0);
  rb_define_method(cDTrace, "error", dtrace_hdl_error, 0);
  rb_define_method(cDTrace, "setopt", dtrace_hdl_setopt, 2);
  rb_define_method(cDTrace, "sleep", dtrace_hdl_sleep, 0);
  rb_define_method(cDTrace, "work", dtrace_hdl_work, -1);
  rb_define_method(cDTrace, "buf_consumer", dtrace_hdl_buf_consumer, 1);
  rb_define_method(cDTrace, "drop_consumer", dtrace_hdl_drop_consumer, 1);
  rb_define_method(cDTrace, "err_consumer", dtrace_hdl_err_consumer, 1);
  rb_define_method(cDTrace, "createprocess", dtrace_hdl_createprocess, 1);
  rb_define_method(cDTrace, "grabprocess", dtrace_hdl_grabprocess, 1);
  rb_define_alloc_func(cDTrace, dtrace_hdl_alloc);

  cDTraceProcess = rb_define_class_under(cDTrace, "Process", rb_cObject);
  rb_define_method(cDTraceProcess, "release", dtrace_process_release, 0);
  rb_define_method(cDTraceProcess, "continue", dtrace_process_continue, 0);

  cDTraceProbeDesc = rb_define_class_under(cDTrace, "ProbeDesc", rb_cObject);
  rb_define_method(cDTraceProbeDesc, "probe_id", dtraceprobedesc_probe_id, 0);
  rb_define_method(cDTraceProbeDesc, "provider", dtraceprobedesc_provider, 0);
  rb_define_method(cDTraceProbeDesc, "mod", dtraceprobedesc_mod, 0);
  rb_define_method(cDTraceProbeDesc, "func", dtraceprobedesc_func, 0);
  rb_define_method(cDTraceProbeDesc, "name", dtraceprobedesc_name, 0);

  cDTraceProbeData = rb_define_class_under(cDTrace, "ProbeData", rb_cObject);
  rb_define_method(cDTraceProbeData, "epid", dtraceprobedata_epid, 0);
  rb_define_method(cDTraceProbeData, "probe", dtraceprobedata_probe, 0);
  rb_define_method(cDTraceProbeData, "cpu", dtraceprobedata_cpu, 0);
  rb_define_method(cDTraceProbeData, "indent", dtraceprobedata_indent, 0);
  rb_define_method(cDTraceProbeData, "prefix", dtraceprobedata_prefix, 0);
  rb_define_method(cDTraceProbeData, "flow", dtraceprobedata_flow, 0);
  rb_define_method(cDTraceProbeData, "each_record", dtraceprobedata_each_record, 0);

  cDTraceBufData = rb_define_class_under(cDTrace, "BufData", rb_cObject);
  rb_define_method(cDTraceBufData, "epid", dtracebufdata_epid, 0);
  rb_define_method(cDTraceBufData, "probe", dtracebufdata_probe, 0);
  rb_define_method(cDTraceBufData, "record", dtracebufdata_record, 0);

  cDTraceProgram = rb_define_class_under(cDTrace, "Program", rb_cObject);
  rb_define_method(cDTraceProgram, "execute", dtraceprogram_exec, 0);
  rb_define_method(cDTraceProgram, "info", dtraceprogram_info, 0);

  cDTraceProgramInfo = rb_define_class_under(cDTrace, "ProgramInfo", rb_cObject);
  rb_define_method(cDTraceProgramInfo, "aggregates_count", dtraceprograminfo_aggregates_count, 0);
  rb_define_method(cDTraceProgramInfo, "recgens_count", dtraceprograminfo_recgens_count, 0);
  rb_define_method(cDTraceProgramInfo, "matches_count", dtraceprograminfo_matches_count, 0);
  rb_define_method(cDTraceProgramInfo, "speculations_count", dtraceprograminfo_speculations_count, 0);

  cDTraceAggData = rb_define_class_under(cDTrace, "AggData", rb_cObject);
  rb_define_method(cDTraceAggData, "value", dtraceaggdata_value, 0);
  rb_define_method(cDTraceAggData, "aggtype", dtraceaggdata_aggtype, 0);

  cDTraceRecDesc = rb_define_class_under(cDTrace, "RecDesc", rb_cObject);
  rb_define_method(cDTraceRecDesc, "action", dtracerecdesc_action, 0);

  cDTraceDropData = rb_define_class_under(cDTrace, "DropData", rb_cObject);
  rb_define_method(cDTraceDropData, "cpu", dtracedropdata_cpu, 0);
  rb_define_method(cDTraceDropData, "drops", dtracedropdata_drops, 0);
  rb_define_method(cDTraceDropData, "total", dtracedropdata_total, 0);
  rb_define_method(cDTraceDropData, "msg", dtracedropdata_msg, 0);
  rb_define_method(cDTraceDropData, "kind", dtracedropdata_kind, 0);

  cDTraceErrData = rb_define_class_under(cDTrace, "ErrData", rb_cObject);
  rb_define_method(cDTraceErrData, "cpu", dtraceerrdata_cpu, 0);
  rb_define_method(cDTraceErrData, "action", dtraceerrdata_action, 0);
  rb_define_method(cDTraceErrData, "offset", dtraceerrdata_offset, 0);
  rb_define_method(cDTraceErrData, "fault", dtraceerrdata_fault, 0);
  rb_define_method(cDTraceErrData, "addr", dtraceerrdata_addr, 0);
  rb_define_method(cDTraceErrData, "msg", dtraceerrdata_msg, 0);

  eDTraceException = rb_define_class_under(cDTrace, "Exception", rb_eStandardError);
}
