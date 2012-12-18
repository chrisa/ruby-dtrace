/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

/* this is a full path because the ruby-dtrace probes add a "dtrace.h"
 * in the same directory as ruby.h, and we must avoid loading that...
 */
#include "/usr/include/dtrace.h"

/* undefine _FILE_OFFSET_BITS: we want the definition from ruby. */
#undef _FILE_OFFSET_BITS

#include "ruby.h"

/* Used to pass three Ruby VALUEs as the void *arg of dtrace_work() to
   its callbacks: the dtrace handle, a Proc for the probe callback,
   and a Proc for the recdesc callback. */
typedef struct dtrace_work_handlers {
  VALUE handle;
  VALUE probe;
  VALUE rec;
} dtrace_work_handlers_t;

/* Used to wrap up the DTrace handle, so we can keep references to the
   various callbacks: we must mark them from the dtrace_hdl_mark
   routine, which only gets a pointer to this structure. */
typedef struct dtrace_handle {
  dtrace_hdl_t *hdl;
  VALUE probe;
  VALUE rec;
  VALUE buf;
  VALUE err;
  VALUE drop;
  VALUE procs;
} dtrace_handle_t;

/* Used to keep a reference to a struct ps_prochandle and a reference
   to the DTrace handle in a DTraceProcess object: we need to be able 
   to call dtrace_proc_release() when the DTraceProcess goes away, and
   that requires the DTrace handle. */
typedef struct dtrace_process {
  dtrace_handle_t *handle;
  struct ps_prochandle *proc;
} dtrace_process_t;

/* Struct wrapping a probe, a handcrafted function created to be a
   probe trigger point, and its corresponding is_enabled tracepoint.

   This is actually a pointer to the is_enabled function (the probe
   function is after) so it's declared to take no args, and return
   int. */
typedef struct dtrace_probe {
  int (*func)();
} dtrace_probe_t;

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
void dtrace_process_free(dtrace_process_t *process);
VALUE dtrace_process_release(VALUE self);
VALUE dtrace_process_continue(VALUE self);

VALUE dtraceaggdata_init(VALUE self);
VALUE dtraceaggdata_value(VALUE self);
VALUE dtraceaggdata_aggtype(VALUE self);

VALUE dtrace_init(VALUE self);
VALUE dtrace_hdl_alloc(VALUE klass);
VALUE dtrace_hdl_close(VALUE self);
VALUE dtrace_each_probe_all(VALUE self);
VALUE dtrace_each_probe_match(VALUE self, VALUE provider, VALUE mod, VALUE func, VALUE name);
VALUE dtrace_each_probe_prog(VALUE self, VALUE program);
VALUE dtrace_strcompile(int argc, VALUE *argv, VALUE self);
VALUE dtrace_hdl_go(VALUE self);
VALUE dtrace_hdl_status(VALUE self);
VALUE dtrace_hdl_setopt(VALUE self, VALUE key, VALUE value);
VALUE dtrace_hdl_stop(VALUE self);
VALUE dtrace_hdl_error(VALUE self);
VALUE dtrace_hdl_sleep(VALUE self);
VALUE dtrace_hdl_work(int argc, VALUE *argv, VALUE self);
VALUE dtrace_hdl_buf_consumer(VALUE self, VALUE buf_consumer_proc);
VALUE dtrace_hdl_drop_consumer(VALUE self, VALUE drop_consumer_proc);
VALUE dtrace_hdl_err_consumer(VALUE self, VALUE err_consumer_proc);
VALUE dtrace_hdl_createprocess(VALUE self, VALUE rbargv);
VALUE dtrace_hdl_grabprocess(VALUE self, VALUE pid);

VALUE dtraceprobedesc_init(VALUE self);
VALUE dtraceprobedesc_probe_id(VALUE self);
VALUE dtraceprobedesc_provider(VALUE self);
VALUE dtraceprobedesc_mod(VALUE self);
VALUE dtraceprobedesc_func(VALUE self);
VALUE dtraceprobedesc_name(VALUE self);

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
VALUE dtracerecdesc_action(VALUE self);

VALUE dtracedropdata_init(VALUE self);
VALUE dtracedropdata_cpu(VALUE self);
VALUE dtracedropdata_drops(VALUE self);
VALUE dtracedropdata_total(VALUE self);
VALUE dtracedropdata_msg(VALUE self);
VALUE dtracedropdata_kind(VALUE self);

VALUE dtraceerrdata_init(VALUE self);
VALUE dtraceerrdata_cpu(VALUE self);
VALUE dtraceerrdata_action(VALUE self);
VALUE dtraceerrdata_offset(VALUE self);
VALUE dtraceerrdata_fault(VALUE self);
VALUE dtraceerrdata_addr(VALUE self);
VALUE dtraceerrdata_msg(VALUE self);

VALUE dtraceprobe_alloc(VALUE klass);
VALUE dtraceprobe_init(VALUE self, VALUE argc);
VALUE dtraceprobe_addr(VALUE self);
VALUE dtraceprobe_fire(int argc, VALUE *argv, VALUE self);
VALUE dtraceprobe_is_enabled(VALUE self);
VALUE dtraceprobe_probe_offset(VALUE self, VALUE rfile, VALUE argc);
VALUE dtraceprobe_is_enabled_offset(VALUE self, VALUE rfile);
