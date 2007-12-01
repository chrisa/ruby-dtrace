/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

RUBY_EXTERN VALUE eDtraceException;
RUBY_EXTERN VALUE cDtraceProbe;
RUBY_EXTERN VALUE cDtraceProgram;
RUBY_EXTERN VALUE cDtraceAggData;

void dtrace_hdl_free (void *handle)
{
  dtrace_close(handle);
}

VALUE dtrace_hdl_alloc(VALUE klass)
{
  dtrace_hdl_t *handle;
  int err;
  VALUE obj;
  
  handle = dtrace_open(DTRACE_VERSION, 0, &err);
  
  if (handle) {
    obj = Data_Wrap_Struct(klass, 0, dtrace_hdl_free, handle);
    return obj;
  }
  else {
    rb_raise(eDtraceException, "unable to open dtrace (not root?)");
  }
}

/* :nodoc: */
VALUE dtrace_init(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (handle)
    return self;
  else
    return Qnil;
}

int _dtrace_next_probe(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp, void *arg)
{
  VALUE probe;

  probe = Data_Wrap_Struct(cDtraceProbe, 0, NULL, (dtrace_probedesc_t *)pdp);

  rb_yield(probe);
  return 0;
}

/*
 * Yields each probe found on the system. 
 * (equivalent to dtrace -l)
 *
 * Each probe is represented by a DtraceProbe object
 */
VALUE dtrace_each_probe(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  (void) dtrace_probe_iter(handle, NULL, _dtrace_next_probe, NULL);

  return self;
}

/*
 * Compile a D program. 
 *
 * Arguments:
 * * The program text to compile
 * * (Optionally) any arguments required by the program
 *
 * Raises a DtraceException if the program cannot be compiled.
 */
VALUE dtrace_strcompile(int argc, VALUE *argv, VALUE self)
{
  dtrace_hdl_t *handle;
  dtrace_prog_t *program;
  VALUE dtrace_program;

  VALUE dtrace_text;
  int dtrace_argc;
  VALUE dtrace_argv_array;

  char **dtrace_argv;
  int i;

  rb_scan_args(argc, argv, "1*", &dtrace_text, &dtrace_argv_array);

  dtrace_argc = FIX2INT(rb_funcall(dtrace_argv_array, rb_intern("length"), 0));
  dtrace_argv = ALLOC_N(char *, dtrace_argc + 1);
  for (i = 0; i < dtrace_argc; i++) {
    dtrace_argv[i + 1] = STR2CSTR(rb_ary_entry(dtrace_argv_array, i));
  }

  dtrace_argv[0] = "ruby";
  dtrace_argc++;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  program = dtrace_program_strcompile(handle, STR2CSTR(dtrace_text),
				      DTRACE_PROBESPEC_NAME, DTRACE_C_PSPEC, 
				      dtrace_argc, dtrace_argv);

  if (!program) {
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    return Qnil;
  }
  else {
    dtrace_program = Data_Wrap_Struct(cDtraceProgram, 0, NULL, program);
    rb_iv_set(dtrace_program, "@dtrace", self);
    return dtrace_program;
  }
}

/*
 * Start tracing. Must be called once a program has been successfully
 * compiled and executed.
 * 
 * Raises a DtraceException on any error.
 */
VALUE dtrace_hdl_go(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (dtrace_go(handle) < 0) 
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;
}

/* 
 * Returns the status of the DTrace handle.
 *
 * Status values are defined as:
 * 
 * * 0 - none
 * * 1 - ok
 * * 4 - stopped
 */
VALUE dtrace_hdl_status(VALUE self)
{
  dtrace_hdl_t *handle;
  int status;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if ((status = dtrace_status(handle)) < 0) 
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return INT2FIX(status);
}

/* 
 * Set an option on the DTrace handle. 
 * 
 * Options which may be set:
 * 
 * * aggsize
 * * bufsize
 */
VALUE dtrace_hdl_setopt(VALUE self, VALUE key, VALUE value)
{
  dtrace_hdl_t *handle;
  int ret;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  
  if (NIL_P(value)) {
    ret = dtrace_setopt(handle, STR2CSTR(key), 0);
  }
  else {
    ret = dtrace_setopt(handle, STR2CSTR(key), STR2CSTR(value));
  }

  if (ret < 0) 
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;
}

/* Stop tracing. 
 *
 * Must be called after go has been called to start tracing.
 */
VALUE dtrace_hdl_stop(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (dtrace_stop(handle) < 0) 
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;
}

int _agg_walk_yield(const dtrace_aggdata_t *data, void *arg)
{
  VALUE aggdata;

  aggdata = Data_Wrap_Struct(cDtraceAggData, 0, NULL, (dtrace_aggdata_t *)data);

  rb_yield(aggdata);
  return (DTRACE_AGGWALK_NEXT);
}

/*
 * Yields each aggregate in turn. 
 * 
 * Aggregates are represented by a DtraceAggregate object.
 */
VALUE dtrace_hdl_each_aggregate(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (dtrace_aggregate_walk_keyvarsorted(handle, _agg_walk_yield, NULL) < 0)
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;    
}

/* 
 * Uses libdtrace to print a summary of aggregates to STDERR.
 */
VALUE dtrace_hdl_aggregate_print(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (dtrace_aggregate_print(handle, stderr, NULL) < 0)
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;
}

/*
 * Take a snapshot of the current aggregate values.
 */
VALUE dtrace_hdl_aggregate_snap(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  if (dtrace_aggregate_snap(handle) < 0) 
    rb_raise(eDtraceException, dtrace_errmsg(handle, dtrace_errno(handle)));
    
  return Qnil;
}

/*
 * Clear the current aggregate snapshot.
 */
VALUE dtrace_hdl_aggregate_clear(VALUE self)
{
  dtrace_hdl_t *handle;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  dtrace_aggregate_clear(handle);
  return Qnil;
}

/* 
 * Return the most recent DTrace error.
 */
VALUE dtrace_hdl_error(VALUE self)
{
  dtrace_hdl_t *handle;
  const char *error_string;

  Data_Get_Struct(self, dtrace_hdl_t, handle);
  error_string = dtrace_errmsg(handle, dtrace_errno(handle));
  return rb_str_new2(error_string);
}

