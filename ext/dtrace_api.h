/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

/* this is a full path because the ruby-dtrace probes add a "dtrace.h"
 * in the same directory as ruby.h, and we must avoid loading that...
 */
#include "/usr/include/dtrace.h"
#include "ruby.h"

/* Used to pass three Ruby VALUEs as the void *arg of dtrace_work() to
   its callbacks: the dtrace handle, a Proc for the probe callback,
   and a Proc for the recdesc callback. */
typedef struct dtrace_work_handlers {
  VALUE handle;
  VALUE probe;
  VALUE rec;
} dtrace_work_handlers_t;

/* Handle missing RARRAY_LEN etc */
#ifdef RARRAY_LEN
static inline long   rb_str_len(VALUE s) {return RSTRING_LEN(s);}
static inline char  *rb_str_ptr(VALUE s) {return RSTRING_PTR(s);}
static inline long   rb_ary_len(VALUE s) {return  RARRAY_LEN(s);}
static inline VALUE *rb_ary_ptr(VALUE s) {return  RARRAY_PTR(s);}
#else
static inline long   rb_str_len(VALUE s) {return RSTRING(s)->len;}
static inline char  *rb_str_ptr(VALUE s) {return RSTRING(s)->ptr;}
static inline long   rb_ary_len(VALUE s) {return  RARRAY(s)->len;}
static inline VALUE *rb_ary_ptr(VALUE s) {return  RARRAY(s)->ptr;}
#endif // RARRAY_LEN

VALUE handle_bytedata(caddr_t addr, uint32_t nbytes);

VALUE dtrace_process_init(VALUE self);
VALUE dtrace_process_continue(VALUE self);

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
VALUE dtrace_hdl_error(VALUE self);
VALUE dtrace_hdl_sleep(VALUE self);
VALUE dtrace_hdl_work(int argc, VALUE *argv, VALUE self);
VALUE dtrace_hdl_buf_consumer(VALUE self, VALUE buf_consumer_proc);
VALUE dtrace_hdl_createprocess(VALUE self, VALUE argv);
VALUE dtrace_hdl_grabprocess(VALUE self, VALUE pid);

VALUE dtraceprobe_init(VALUE self);
VALUE dtraceprobe_probe_id(VALUE self);
VALUE dtraceprobe_provider(VALUE self);
VALUE dtraceprobe_mod(VALUE self);
VALUE dtraceprobe_func(VALUE self);
VALUE dtraceprobe_name(VALUE self);

VALUE dtraceprobedata_init(VALUE self);
VALUE dtraceprobedata_epid(VALUE self);
VALUE dtraceprobedata_probe(VALUE self);
VALUE dtraceprobedata_cpu(VALUE self);
VALUE dtraceprobedata_indent(VALUE self);
VALUE dtraceprobedata_prefix(VALUE self);
VALUE dtraceprobedata_flow(VALUE self);
VALUE dtraceprobedata_each_record(VALUE self);

VALUE dtracebufdata_init(VALUE self);
VALUE dtracebufdata_epid(VALUE self);
VALUE dtracebufdata_probe(VALUE self);
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
