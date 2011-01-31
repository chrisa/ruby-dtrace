/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"
#include <errno.h>
#include <string.h>

RUBY_EXTERN eDtraceDofException;

/* :nodoc: */
VALUE dof_generate_section_header(VALUE self) {
  VALUE hdr_data;
  dof_sec_t hdr;
  uint32_t type;
  uint64_t offset;
  uint64_t size;
  uint32_t entsize;

  memset(&hdr, 0, sizeof(hdr));
  hdr.dofs_flags   = FIX2INT(rb_iv_get(self, "@flags"));
  hdr.dofs_type    = FIX2INT(rb_iv_get(self, "@section_type"));
  hdr.dofs_offset  = FIX2INT(rb_iv_get(self, "@offset"));
  hdr.dofs_size    = FIX2INT(rb_iv_get(self, "@size"));
  hdr.dofs_entsize = FIX2INT(rb_iv_get(self, "@entsize"));
  hdr.dofs_align   = FIX2INT(rb_iv_get(self, "@align"));

  hdr_data = rb_str_new((const char *)&hdr, sizeof(hdr));
  return hdr_data;
}

/* :nodoc: */
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

/* :nodoc: */
VALUE dof_generate_probes(VALUE self) {
  VALUE dof;
  VALUE probes = rb_iv_get(self, "@data");
  VALUE probe;
  int i;
  
  if (NIL_P(probes) ) {
    rb_raise(eDtraceDofException, "no probes in dof_generate_probes");
    return Qnil;
  }
  Check_Type(probes, T_ARRAY);
 
  dof = rb_str_new2("");

  for (i = 0; i < rb_ary_len(probes); i++) {
    probe = rb_ary_entry(probes, i);

    Check_Type(probe, T_HASH);

    dof_probe_t p;
    memset(&p, 0, sizeof(p));
    
    p.dofpr_addr  =     (uint64_t)NUM2LL(rb_hash_aref(probe, ID2SYM(rb_intern("addr"))));
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

/* :nodoc: */
VALUE dof_generate_strtab(VALUE self) {
  VALUE dof;
  VALUE strings = rb_iv_get(self, "@data");
  VALUE string;
  int i;
  
  if (NIL_P(strings) ) {
    rb_raise(eDtraceDofException, "no strings in dof_generate_strtab");
    return Qnil;
  }
  Check_Type(strings, T_ARRAY);
 
  dof = rb_str_new("", 0);
  rb_str_concat(dof, rb_str_new("\0", 1));
 
  for (i = 0; i < rb_ary_len(strings); i++) {
    string = rb_ary_entry(strings, i);

    Check_Type(string, T_STRING);

    rb_str_concat(dof, rb_str_new(RSTRING(string)->ptr, RSTRING(string)->len + 1));
  }
  
  return dof;
}
  
/* :nodoc: */
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

/* :nodoc: */
VALUE dof_generate_prargs(VALUE self) {
  VALUE dof;
  VALUE args = rb_iv_get(self, "@data");
  VALUE rarg;
  uint8_t arg;
  int i;
  
  if (NIL_P(args) ) {
    rb_raise(eDtraceDofException, "no args in dof_generate_prargs");
    return Qnil;
  }
  Check_Type(args, T_ARRAY);
 
  dof = rb_str_new("", 0);
 
  for (i = 0; i < rb_ary_len(args); i++) {
    rarg = rb_ary_entry(args, i);
    Check_Type(rarg, T_FIXNUM);
    if (FIX2INT(rarg) >= 0 && FIX2INT(rarg) < 256) {
      arg = FIX2INT(rarg);
      rb_str_concat(dof, rb_str_new((char *)&arg, 1));
    }
  }
  
  return dof;
}

/* :nodoc: */
VALUE dof_generate_proffs(VALUE self) {
  VALUE dof;
  VALUE args = rb_iv_get(self, "@data");
  VALUE rarg;
  uint32_t arg;
  int i;
  
  if (NIL_P(args) ) {
    rb_raise(eDtraceDofException, "no args in dof_generate_proffs");
    return Qnil;
  }
  Check_Type(args, T_ARRAY);
 
  dof = rb_str_new("", 0);
 
  for (i = 0; i < rb_ary_len(args); i++) {
    rarg = rb_ary_entry(args, i);
    Check_Type(rarg, T_FIXNUM);
    arg = FIX2INT(rarg);
    rb_str_concat(dof, rb_str_new((char *)&arg, 4));
  }
  
  return dof;
}

/* :nodoc: */
VALUE dof_generate_prenoffs(VALUE self) {
  VALUE dof;
  VALUE args = rb_iv_get(self, "@data");
  VALUE rarg;
  uint32_t arg;
  int i;
  
  if (NIL_P(args) ) {
    rb_raise(eDtraceDofException, "no args in dof_generate_prenoffs");
    return Qnil;
  }
  Check_Type(args, T_ARRAY);
 
  dof = rb_str_new("", 0);
 
  for (i = 0; i < rb_ary_len(args); i++) {
    rarg = rb_ary_entry(args, i);
    Check_Type(rarg, T_FIXNUM);
    arg = FIX2INT(rarg);
    rb_str_concat(dof, rb_str_new((char *)&arg, 4));
  }
  
  return dof;
}

dof_attr_t _dof_generate_dof_attr_t(VALUE data) {
  dof_attr_t attr = 0;
  uint8_t n = 0;
  uint8_t d = 0;
  uint8_t c = 0;

  Check_Type(data, T_HASH);

  n = FIX2INT(rb_hash_aref(data, ID2SYM(rb_intern("name"))));
  d = FIX2INT(rb_hash_aref(data, ID2SYM(rb_intern("data"))));
  c = FIX2INT(rb_hash_aref(data, ID2SYM(rb_intern("class"))));

  attr = DOF_ATTR(n, d, c);
  return attr;
}

/* :nodoc: */
VALUE dof_generate_provider(VALUE self) {
  VALUE dof;
  VALUE provider = rb_iv_get(self, "@data");
  dof_provider_t p;
  
  if (NIL_P(provider) ) {
    rb_raise(eDtraceDofException, "no data in dof_generate_provider");
    return Qnil;
  }
  Check_Type(provider, T_HASH);
    
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

/* :nodoc: */
VALUE dof_generate_reltab(VALUE self) {
  VALUE dof;
  VALUE relos = rb_iv_get(self, "@data");
  VALUE relo;
  int i;
  
  if (NIL_P(relos) ) {
    rb_raise(eDtraceDofException, "no relos in dof_generate_reltab");
    return Qnil;
  }
  Check_Type(relos, T_ARRAY);
 
  dof = rb_str_new2("");

  for (i = 0; i < rb_ary_len(relos); i++) {
    relo = rb_ary_entry(relos, i);

    Check_Type(relo, T_HASH);

    dof_relodesc_t r;
    memset(&r, 0, sizeof(r));
    
    r.dofr_name   = (dof_stridx_t)FIX2INT(rb_hash_aref(relo, ID2SYM(rb_intern("name"))));
    r.dofr_type   =     (uint32_t)FIX2INT(rb_hash_aref(relo, ID2SYM(rb_intern("type"))));
    r.dofr_offset =     (uint64_t)FIX2INT(rb_hash_aref(relo, ID2SYM(rb_intern("offset"))));
    r.dofr_data   =     (uint64_t)FIX2INT(rb_hash_aref(relo, ID2SYM(rb_intern("data"))));
    
    VALUE r_dof = rb_str_new((const char *)&r, sizeof(r));
    rb_str_concat(dof, r_dof);
  }

  return dof;
}

/* :nodoc: */
VALUE dof_generate_relhdr(VALUE self) {
  VALUE dof;
  VALUE relhdr = rb_iv_get(self, "@data");
  dof_relohdr_t r;
  
  if (NIL_P(relhdr) ) {
    rb_raise(eDtraceDofException, "no data in dof_generate_relhdr");
    return Qnil;
  }
  Check_Type(relhdr, T_HASH);
  
  r.dofr_strtab = (dof_secidx_t)FIX2INT(rb_hash_aref(relhdr, ID2SYM(rb_intern("strtab"))));
  r.dofr_relsec = (dof_secidx_t)FIX2INT(rb_hash_aref(relhdr, ID2SYM(rb_intern("relsec"))));
  r.dofr_tgtsec = (dof_secidx_t)FIX2INT(rb_hash_aref(relhdr, ID2SYM(rb_intern("tgtsec"))));  
    
  dof = rb_str_new((const char *)&r, sizeof(r));
  return dof;
}

