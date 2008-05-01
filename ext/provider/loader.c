/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include <ruby.h>
#include <dlfcn.h>

VALUE cDtraceProviderLoader;

static VALUE dtrace_provider_load(VALUE class, VALUE name, VALUE path) {
  long handle;
  handle = (long)dln_load(RSTRING(path)->ptr);
  fprintf(stderr, "handle: 0x%x\n", handle);
  rb_hash_aset(rb_cv_get(class, "@@handles"), name, INT2FIX(handle));

  return Qnil;
}

static VALUE dtrace_provider_unload(VALUE class, VALUE name) {
  long handle;
  handle = FIX2LONG(rb_hash_aref(rb_cv_get(class, "@@handles"), name));
  fprintf(stderr, "handle: 0x%x\n", handle);
  if (dlclose((void *)handle) < 0) {
    return rb_str_new2(dlerror());
  }

  return Qnil;
}

static VALUE dtrace_provider_handles(VALUE class) {
  return rb_cv_get(class, "@@handles");
}

void Init_loader() {
  cDtraceProviderLoader = rb_define_class("DtraceProviderLoader", rb_cObject);
  rb_define_singleton_method(cDtraceProviderLoader, "load",    dtrace_provider_load,    2);
  rb_define_singleton_method(cDtraceProviderLoader, "unload",  dtrace_provider_unload,  1);
  rb_define_singleton_method(cDtraceProviderLoader, "handles", dtrace_provider_handles, 0);
  rb_cv_set(cDtraceProviderLoader, "@@handles", rb_hash_new());
}  
