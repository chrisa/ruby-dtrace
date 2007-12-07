/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

/* this is a full path because the ruby-dtrace probes add a "dtrace.h"
 * in the same directory as ruby.h, and we must avoid loading that...
 */
#include "/usr/include/dtrace.h"
#include "ruby.h"

VALUE handle_bytedata(caddr_t addr, uint32_t nbytes);

VALUE dtraceaggdata_init(VALUE self);
VALUE dtraceaggdata_value(VALUE self);
VALUE dtraceaggdata_aggtype(VALUE self);

void  dtrace_hdl_free (void *handle);
VALUE dtrace_hdl_alloc(VALUE klass);
VALUE dtrace_init(VALUE self);
VALUE dtrace_each_probe(VALUE self);
VALUE dtrace_strcompile(int argc, VALUE *argv, VALUE self);
VALUE dtrace_hdl_go(VALUE self);
VALUE dtrace_hdl_status(VALUE self);
VALUE dtrace_hdl_setopt(VALUE self, VALUE key, VALUE value);
VALUE dtrace_hdl_stop(VALUE self);
VALUE dtrace_hdl_each_aggregate(VALUE self);
VALUE dtrace_hdl_aggregate_print(VALUE self);
VALUE dtrace_hdl_aggregate_snap(VALUE self);
VALUE dtrace_hdl_aggregate_clear(VALUE self);
VALUE dtrace_hdl_error(VALUE self);
VALUE dtrace_hdl_sleep(VALUE self);
VALUE dtrace_hdl_work(VALUE self, 
		      VALUE probe_consumer_proc, 
		      VALUE rec_consumer_proc);
VALUE dtrace_hdl_buf_consumer(VALUE self, VALUE buf_consumer_proc);

VALUE dtraceprobe_init(VALUE self);
VALUE dtraceprobe_probe_id(VALUE self);
VALUE dtraceprobe_provider(VALUE self);
VALUE dtraceprobe_mod(VALUE self);
VALUE dtraceprobe_func(VALUE self);
VALUE dtraceprobe_name(VALUE self);

VALUE dtraceprobedata_init(VALUE self);
VALUE dtraceprobedata_probedesc(VALUE self);
VALUE dtraceprobedata_each_record(VALUE self);

VALUE dtracebufdata_init(VALUE self);
VALUE dtracebufdata_record(VALUE self);

VALUE dtraceprogram_init(VALUE self);
VALUE dtraceprogram_exec(VALUE self);
VALUE dtraceprogram_info(VALUE self);

VALUE dtraceprograminfo_init(VALUE self);
VALUE dtraceprograminfo_aggregates_count(VALUE self);
VALUE dtraceprograminfo_recgens_count(VALUE self);
VALUE dtraceprograminfo_matches_count(VALUE self);
VALUE dtraceprograminfo_speculations_count(VALUE self);

VALUE dtracerecdesc_init(VALUE self);
