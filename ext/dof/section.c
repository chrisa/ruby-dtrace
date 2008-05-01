/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"
#include <errno.h>
#include <string.h>

RUBY_EXTERN eDtraceDofException;

VALUE dof_generate_section_header(VALUE self) {
  VALUE hdr_data;
  dof_sec_t hdr;
  uint32_t type;
  uint64_t offset;
  uint64_t size;
  VALUE data;
  uint32_t entsize;

  memset(&hdr, 0, sizeof(hdr));
  hdr.dofs_flags = DOF_SECF_LOAD;

  type = FIX2INT(rb_iv_get(self, "@section_type"));
  hdr.dofs_type = type;

  offset = FIX2INT(rb_iv_get(self, "@offset"));
  hdr.dofs_offset = offset;

  size = FIX2INT(rb_iv_get(self, "@size"));
  hdr.dofs_size = size;

  data = rb_iv_get(self, "@data");
  if (TYPE(data) == T_ARRAY) {
    /* XXX entsize is size of each element of the array in bytes */
    entsize = rb_funcall(data, rb_intern("length"), 0);
    hdr.dofs_entsize = entsize;
  }

  hdr_data = rb_str_new((const char *)&hdr, sizeof(hdr));
  return hdr_data;
}

VALUE dof_generate_comments(VALUE self) {
  VALUE dof;
  VALUE comments = rb_iv_get(self, "@data");

  if (NIL_P(comments) ) {
    rb_raise(eDtraceDofException, "no comments in dof_generate_comments");
    return Qnil;
  }
  
  Check_Type(comments, T_STRING);

  dof = rb_str_new(RSTRING(comments)->ptr, RSTRING(comments)->len + 1);
  return dof;
}

VALUE dof_generate_probes(VALUE self) {
  VALUE dof;
  VALUE probes = rb_iv_get(self, "@data");
  VALUE probe;
  
  if (NIL_P(probes) ) {
    rb_raise(eDtraceDofException, "no probes in dof_generate_probes");
    return Qnil;
  }
  Check_Type(probes, T_ARRAY);
 
  dof = rb_str_new2("");

  while (probe = rb_ary_shift(probes)) {
    if (NIL_P(probe))
      break;

    Check_Type(probe, T_HASH);

    dof_probe_t p;
    memset(&p, 0, sizeof(p));
    
    p.dofpr_addr  =     (uint64_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("addr"))));
    p.dofpr_func  = (dof_stridx_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("func"))));
    p.dofpr_name  = (dof_stridx_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("name"))));
    p.dofpr_nargv = (dof_stridx_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("nargv"))));
    p.dofpr_xargv = (dof_stridx_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("xargv"))));
    
    p.dofpr_argidx   = (uint32_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("argidx"))));
    p.dofpr_offidx   = (uint32_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("offidx"))));
    p.dofpr_nargc    =  (uint8_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("nargc"))));
    p.dofpr_xargc    =  (uint8_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("xargc"))));
    p.dofpr_noffs    = (uint16_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("noffs"))));
    p.dofpr_enoffidx = (uint32_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("enoffidx"))));
    p.dofpr_nenoffs  = (uint16_t)FIX2INT(rb_hash_aref(probe, ID2SYM(rb_intern("nenoffs"))));

    VALUE p_dof = rb_str_new((const char *)&p, sizeof(p));
    rb_str_concat(dof, p_dof);
  }

  return dof;
}

VALUE dof_generate_strtab(VALUE self) {
  VALUE dof;
  VALUE strings = rb_iv_get(self, "@data");
  VALUE string;
  
  if (NIL_P(strings) ) {
    rb_raise(eDtraceDofException, "no strings in dof_generate_strtab");
    return Qnil;
  }
  Check_Type(strings, T_ARRAY);
 
  dof = rb_str_new("", 0);
  rb_str_concat(dof, rb_str_new("\0", 1));
 
  while (string = rb_ary_shift(strings)) {
    if (NIL_P(string))
      break;
    Check_Type(string, T_STRING);

    rb_str_concat(dof, rb_str_new(RSTRING(string)->ptr, RSTRING(string)->len + 1));
  }
  
  return dof;
}
  
VALUE dof_generate_utsname(VALUE self) {
  VALUE dof;
  struct utsname u;

  if (uname(&u) < 0) {
    rb_raise(eDtraceDofException, "uname failed: %s", strerror(errno));
    return Qnil;
  }
  
  dof = rb_str_new((const char *)&u, sizeof(struct utsname));
  return dof;
}

VALUE dof_generate_prargs(VALUE self) {
  VALUE dof;
  VALUE args = rb_iv_get(self, "@data");
  VALUE rarg;
  uint8_t arg;
  
  if (NIL_P(args) ) {
    rb_raise(eDtraceDofException, "no args in dof_generate_prargs");
    return Qnil;
  }
  Check_Type(args, T_ARRAY);
 
  dof = rb_str_new("", 0);
 
  while (rarg = rb_ary_shift(args)) {
    if (NIL_P(rarg))
      break;
    Check_Type(rarg, T_FIXNUM);
    if (FIX2INT(rarg) >= 0 && FIX2INT(rarg) < 256) {
      arg = FIX2INT(rarg);
      rb_str_concat(dof, rb_str_new((char *)&arg, 1));
    }
  }
  
  return dof;
}

VALUE dof_generate_proffs(VALUE self) {
  VALUE dof;
  VALUE args = rb_iv_get(self, "@data");
  VALUE rarg;
  uint32_t arg;
  
  if (NIL_P(args) ) {
    rb_raise(eDtraceDofException, "no args in dof_generate_proffs");
    return Qnil;
  }
  Check_Type(args, T_ARRAY);
 
  dof = rb_str_new("", 0);
 
  while (rarg = rb_ary_shift(args)) {
    if (NIL_P(rarg))
      break;
    Check_Type(rarg, T_FIXNUM);
    arg = FIX2INT(rarg);
    rb_str_concat(dof, rb_str_new((char *)&arg, 4));
  }
  
  return dof;
}

dof_attr_t _dof_generate_dof_attr_t(VALUE data) {
  dof_attr_t attr = 0;
  short n = 0;
  short d = 0;
  short c = 0;

  Check_Type(data, T_HASH);

  n = rb_hash_aref(data, ID2SYM(rb_intern("name")));
  d = rb_hash_aref(data, ID2SYM(rb_intern("data")));
  c = rb_hash_aref(data, ID2SYM(rb_intern("class")));

  attr = DOF_ATTR(n, d, c);
  return attr;
}

VALUE dof_generate_provider(VALUE self) {
  VALUE dof;
  VALUE provider = rb_iv_get(self, "@data");
  dof_provider_t p;
  
  if (NIL_P(provider) ) {
    rb_raise(eDtraceDofException, "no data in dof_generate_provider");
    return Qnil;
  }
  Check_Type(provider, T_HASH);

/*     727 typedef struct dof_provider { */
/*     728 	dof_secidx_t dofpv_strtab;	/\* link to DOF_SECT_STRTAB section *\/ */
/*     729 	dof_secidx_t dofpv_probes;	/\* link to DOF_SECT_PROBES section *\/ */
/*     730 	dof_secidx_t dofpv_prargs;	/\* link to DOF_SECT_PRARGS section *\/ */
/*     731 	dof_secidx_t dofpv_proffs;	/\* link to DOF_SECT_PROFFS section *\/ */
/*     732 	dof_stridx_t dofpv_name;	/\* provider name string *\/ */
/*     733 	dof_attr_t dofpv_provattr;	/\* provider attributes *\/ */
/*     734 	dof_attr_t dofpv_modattr;	/\* module attributes *\/ */
/*     735 	dof_attr_t dofpv_funcattr;	/\* function attributes *\/ */
/*     736 	dof_attr_t dofpv_nameattr;	/\* name attributes *\/ */
/*     737 	dof_attr_t dofpv_argsattr;	/\* args attributes *\/ */
/*     738 	dof_secidx_t dofpv_prenoffs;	/\* link to DOF_SECT_PRENOFFS section *\/ */
/*     739 } dof_provider_t; */
    
  p.dofpv_strtab   = (dof_secidx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("strtab"))));
  p.dofpv_probes   = (dof_secidx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("probes"))));
  p.dofpv_prargs   = (dof_secidx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("prargs"))));
  p.dofpv_proffs   = (dof_secidx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("proffs"))));
  p.dofpv_name     = (dof_stridx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("name"))));
  p.dofpv_provattr = _dof_generate_dof_attr_t(rb_hash_aref(provider, ID2SYM(rb_intern("provattr"))));
  p.dofpv_modattr  = _dof_generate_dof_attr_t(rb_hash_aref(provider, ID2SYM(rb_intern("modattr"))));
  p.dofpv_funcattr = _dof_generate_dof_attr_t(rb_hash_aref(provider, ID2SYM(rb_intern("funcattr"))));
  p.dofpv_nameattr = _dof_generate_dof_attr_t(rb_hash_aref(provider, ID2SYM(rb_intern("nameattr"))));
  p.dofpv_argsattr = _dof_generate_dof_attr_t(rb_hash_aref(provider, ID2SYM(rb_intern("argsattr"))));
  p.dofpv_prenoffs = (dof_secidx_t)FIX2INT(rb_hash_aref(provider, ID2SYM(rb_intern("prenoffs"))));
  
  dof = rb_str_new((const char *)&p, sizeof(p));
  return dof;
}
