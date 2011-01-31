/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

RUBY_EXTERN eDtraceDofException;

static void
rubydump(void *data, int len)
{
  VALUE str;
  VALUE dumped;
  char *out;

  str = rb_str_new(data, len);
  dumped = rb_funcall(str, rb_intern("inspect"), 0);
  out = STR2CSTR(dumped);

  fprintf(stderr, "%s\n", out);
}

static void
rubyinspect(VALUE data)
{
  VALUE dumped;
  char *out;

  dumped = rb_funcall(data, rb_intern("inspect"), 0);
  out = STR2CSTR(dumped);

  fprintf(stderr, "%s\n", out);
}

static const char *
_dof_sec_type(uint32_t type)
{
  switch(type) {
  case DOF_SECT_NONE:
    return "null section";
  case DOF_SECT_COMMENTS:
    return "compiler comments";
  case DOF_SECT_SOURCE:
    return "D program source code";
  case DOF_SECT_ECBDESC:
    return "dof_ecbdesc_t";
  case DOF_SECT_PROBEDESC:
    return "dof_probedesc_t";
  case DOF_SECT_ACTDESC:
    return "dof_actdesc_t array";
  case DOF_SECT_DIFOHDR:
    return "dof_difohdr_t (variable length)";
  case DOF_SECT_DIF:
    return "uint32_t array of byte code";
  case DOF_SECT_STRTAB:
    return "string table";
  case DOF_SECT_VARTAB:
    return "dtrace_difv_t array";
  case DOF_SECT_RELTAB:
    return "dof_relodesc_t array";
  case DOF_SECT_TYPTAB:
    return "dtrace_diftype_t array";
  case DOF_SECT_URELHDR:
    return "dof_relohdr_t (user relocations)";
  case DOF_SECT_KRELHDR:
    return "dof_relohdr_t (kernel relocations)";
  case DOF_SECT_OPTDESC:
    return "dof_optdesc_t array";
  case DOF_SECT_PROVIDER:
    return "dof_provider_t";
  case DOF_SECT_PROBES:
    return "dof_probe_t array";
  case DOF_SECT_PRARGS:
    return "uint8_t array (probe arg mappings)";
  case DOF_SECT_PROFFS:
    return "uint32_t array (probe arg offsets)";
  case DOF_SECT_INTTAB:
    return "uint64_t array";
  case DOF_SECT_UTSNAME:
    return "struct utsname";
  case DOF_SECT_XLTAB:
    return "dof_xlref_t array";
  case DOF_SECT_XLMEMBERS:
    return "dof_xlmember_t array";
  case DOF_SECT_XLIMPORT:
    return "dof_xlator_t";
  case DOF_SECT_XLEXPORT:
    return "dof_xlator_t";
  case DOF_SECT_PREXPORT:
    return "dof_secidx_t array (exported objs)";
  case DOF_SECT_PRENOFFS:
    return "uint32_t array (enabled offsets)";
  default:
    return "unknown section type";
  }
}

static VALUE
_dof_parse_string_table(VALUE self, char *dof, dof_sec_t *sec)
{
  char *data = (char *)(dof + sec->dofs_offset);

  VALUE strtab = rb_hash_new();
  VALUE ctx = rb_cv_get(self, "@@ctx");
  int i, bool = 0;
  
  for (i = 0; i < sec->dofs_size - 1; ++i) {
    if (*data) {
      if (bool)
	rb_hash_aset(strtab, INT2FIX(i), rb_str_new2(data));
      bool = 0;
    } 
    else if (!bool) {
      bool = 1;
    }
    ++data;
  }

  rb_hash_aset(ctx, ID2SYM(rb_intern("strtab")), strtab);
  return strtab;
}

static VALUE
_dof_parse_dof_probe_t_array(VALUE self, char *dof, dof_sec_t *sec)
{
  dof_probe_t probe;
  char *data = (char *)(dof + sec->dofs_offset);
  VALUE probes = rb_ary_new();
  VALUE ctx = rb_cv_get(self, "@@ctx");
  VALUE strtab;
  VALUE probe_data;
  char addr_str[18]; // XXX length of pointer as string?
  int count = 0;
  int offset = 0;

  strtab = rb_hash_aref(ctx, ID2SYM(rb_intern("strtab")));
  if (NIL_P(strtab)) {
    rb_raise(eDtraceDofException, "no string table available while parsing probe_t array");
    return Qnil;
  }

  while (offset < sec->dofs_size) {
    memcpy(&probe, dof + sec->dofs_offset + offset, sizeof(probe));
    count++;

    probe_data = rb_hash_new();
    sprintf(addr_str, "%p", (void *)probe.dofpr_addr);
    rb_hash_aset(probe_data, ID2SYM(rb_intern("addr")), rb_str_new2(addr_str));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("func")), rb_hash_aref(strtab, INT2FIX(probe.dofpr_func)));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("name")), rb_hash_aref(strtab, INT2FIX(probe.dofpr_name)));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("nargv")), rb_hash_aref(strtab, INT2FIX(probe.dofpr_nargv)));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("xargv")), rb_hash_aref(strtab, INT2FIX(probe.dofpr_xargv)));

    rb_hash_aset(probe_data, ID2SYM(rb_intern("argidx")),   INT2FIX(probe.dofpr_argidx));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("offidx")),   INT2FIX(probe.dofpr_offidx));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("nargc")),    INT2FIX(probe.dofpr_nargc));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("xargc")),    INT2FIX(probe.dofpr_xargc));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("noffs")),    INT2FIX(probe.dofpr_noffs));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("enoffidx")), INT2FIX(probe.dofpr_enoffidx));
    rb_hash_aset(probe_data, ID2SYM(rb_intern("nenoffs")),  INT2FIX(probe.dofpr_nenoffs));

    rb_ary_push(probes, probe_data);
    offset += sizeof(probe);
  }

  return probes;
}

static VALUE
_dof_parse_dof_relodesc_t_array(VALUE self, char *dof, dof_sec_t *sec)
{
  dof_relodesc_t relodesc;
  char *data = (char *)(dof + sec->dofs_offset);
  VALUE relodescs = rb_ary_new();
  VALUE ctx = rb_cv_get(self, "@@ctx");
  VALUE strtab = rb_hash_aref(ctx, ID2SYM(rb_intern("strtab")));
  VALUE relodesc_data;
  int count = 0;
  int offset = 0;

  while (offset < sec->dofs_size) {
    memcpy(&relodesc, dof + sec->dofs_offset + offset, sizeof(relodesc));
    count++;

    relodesc_data = rb_hash_new();
    rb_hash_aset(relodesc_data, ID2SYM(rb_intern("name")), rb_hash_aref(strtab, INT2FIX(relodesc.dofr_name)));
    
    switch(relodesc.dofr_type) {
    case DOF_RELO_NONE:
      rb_hash_aset(relodesc_data, ID2SYM(rb_intern("type")), rb_str_new2("none"));
      break;
    case DOF_RELO_SETX:
      rb_hash_aset(relodesc_data, ID2SYM(rb_intern("type")), rb_str_new2("setx"));
      break;
    default:
      rb_hash_aset(relodesc_data, ID2SYM(rb_intern("type")), rb_str_new2("unknown"));
      break;
    }
    
    rb_hash_aset(relodesc_data, ID2SYM(rb_intern("offset")), INT2FIX(relodesc.dofr_offset));
    rb_hash_aset(relodesc_data, ID2SYM(rb_intern("data")),   INT2FIX(relodesc.dofr_data));

    rb_ary_push(relodescs, relodesc_data);
    offset += sizeof(relodesc);
  }

  return relodescs;
}

static VALUE
_dof_parse_dof_relohdr_t(VALUE self, char *dof, dof_sec_t *sec)
{
  dof_relohdr_t relohdr;
  char *data = (char *)(dof + sec->dofs_offset);
  VALUE relohdr_data = rb_hash_new();

  memcpy(&relohdr, dof + sec->dofs_offset, sizeof(relohdr));
  rb_hash_aset(relohdr_data, ID2SYM(rb_intern("strtab")), INT2FIX(relohdr.dofr_strtab));
  rb_hash_aset(relohdr_data, ID2SYM(rb_intern("relsec")), INT2FIX(relohdr.dofr_relsec));
  rb_hash_aset(relohdr_data, ID2SYM(rb_intern("tgtsec")), INT2FIX(relohdr.dofr_tgtsec));

  return relohdr_data;
}

static VALUE
_dof_parse_dof_attr_t(dof_attr_t attr)
{
  VALUE attr_data = rb_hash_new();

  rb_hash_aset(attr_data, ID2SYM(rb_intern("name")),  INT2FIX(DOF_ATTR_NAME(attr)));
  rb_hash_aset(attr_data, ID2SYM(rb_intern("data")),  INT2FIX(DOF_ATTR_DATA(attr)));
  rb_hash_aset(attr_data, ID2SYM(rb_intern("class")), INT2FIX(DOF_ATTR_CLASS(attr)));
  
  return attr_data;
}

static VALUE
_dof_parse_dof_provider_t(VALUE self, char *dof, dof_sec_t *sec)
{
  dof_provider_t provider;
  char *data = (char *)(dof + sec->dofs_offset);
  VALUE provider_data = rb_hash_new();
  VALUE ctx = rb_cv_get(self, "@@ctx");
  VALUE strtab = rb_hash_aref(ctx, ID2SYM(rb_intern("strtab")));

  memcpy(&provider, dof + sec->dofs_offset, sizeof(provider));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("name")), rb_hash_aref(strtab, INT2FIX(provider.dofpv_name)));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("strtab")), INT2FIX(provider.dofpv_strtab));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("probes")), INT2FIX(provider.dofpv_probes));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("prargs")), INT2FIX(provider.dofpv_prargs));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("proffs")), INT2FIX(provider.dofpv_proffs));

  rb_hash_aset(provider_data, ID2SYM(rb_intern("provattr")), _dof_parse_dof_attr_t(provider.dofpv_provattr));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("modattr")),  _dof_parse_dof_attr_t(provider.dofpv_modattr));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("funcattr")), _dof_parse_dof_attr_t(provider.dofpv_funcattr));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("nameattr")), _dof_parse_dof_attr_t(provider.dofpv_nameattr));
  rb_hash_aset(provider_data, ID2SYM(rb_intern("argsattr")), _dof_parse_dof_attr_t(provider.dofpv_argsattr));

  return provider_data;
}

static VALUE
_dof_parse_uint8_t_array(VALUE self, char *dof, dof_sec_t *sec)
{
  VALUE ary_data = rb_ary_new();
  char *data = (char *)(dof + sec->dofs_offset);
  int len = sec->dofs_size / sizeof(uint8_t);
  uint8_t array[len];
  int i;

  memcpy(&array, data, len * sizeof(uint8_t));
  for (i = 0; i < len; i++) {
    rb_ary_push(ary_data, INT2FIX(array[i]));
  }

  return ary_data;
}

static VALUE
_dof_parse_uint32_t_array(VALUE self, char *dof, dof_sec_t *sec)
{
  VALUE ary_data = rb_ary_new();
  char *data = (char *)(dof + sec->dofs_offset);
  int len = sec->dofs_size / sizeof(uint32_t);
  uint32_t array[len];
  int i;

  memcpy(&array, data, len * sizeof(uint32_t));
  for (i = 0; i < len; i++) {
    rb_ary_push(ary_data, INT2FIX((unsigned int)array[i]));
  }

  return ary_data;
}

static VALUE
_dof_parse_comments(VALUE self, char *dof, dof_sec_t *sec)
{
  char comment[sec->dofs_size + 1];
  char *data = (char *)(dof + sec->dofs_offset);

  strncpy(comment, data, sec->dofs_size);
  return rb_str_new2(comment);
}

static VALUE
_dof_parse_utsname(VALUE self, char *dof, dof_sec_t *sec)
{
  struct utsname uts;
  VALUE uts_data = rb_hash_new();
  char *data = (char *)(dof + sec->dofs_offset);

  memcpy(&uts, data, sizeof(uts));
  
  rb_hash_aset(uts_data, ID2SYM(rb_intern("sysname")),  rb_str_new2(uts.sysname));
  rb_hash_aset(uts_data, ID2SYM(rb_intern("nodename")), rb_str_new2(uts.nodename));
  rb_hash_aset(uts_data, ID2SYM(rb_intern("release")),  rb_str_new2(uts.release));
  rb_hash_aset(uts_data, ID2SYM(rb_intern("version")),  rb_str_new2(uts.version));
  rb_hash_aset(uts_data, ID2SYM(rb_intern("machine")),  rb_str_new2(uts.machine));

  return uts_data;
}

static VALUE
_dof_parse_unknown(VALUE self, char *dof, dof_sec_t *sec)
{
  VALUE section_data = rb_hash_new();
  return section_data;
}

/* Parse the given DOF */
VALUE dof_parse(VALUE self, VALUE rdof)
{
  VALUE dof_data;
  VALUE sec_data;
  VALUE ctx;
  VALUE sec;
  char *dof;
  char *pos;
  dof_hdr_t dof_hdr;
  dof_sec_t dof_sec;
  int i;

  ctx = rb_hash_new();
  rb_cv_set(self, "@@ctx", ctx);

  dof = STR2CSTR(rdof);
  pos = dof;
  memcpy(&dof_hdr, pos, sizeof(dof_hdr));

  /* Check magic */
  if (!(dof_hdr.dofh_ident[0] == DOF_MAG_MAG0 &&
	dof_hdr.dofh_ident[1] == DOF_MAG_MAG1 &&
	dof_hdr.dofh_ident[2] == DOF_MAG_MAG2 &&
	dof_hdr.dofh_ident[3] == DOF_MAG_MAG3)) {
    rb_raise(eDtraceDofException, "bad DOF header magic");
    return Qnil;
  }
  pos += dof_hdr.dofh_hdrsize;
  
  dof_data = rb_ary_new();
  
  /* Walk section headers, parsing sections */
  for (i = 0; i < dof_hdr.dofh_secnum; i++) {
    memcpy(&dof_sec, pos, sizeof(struct dof_sec));

    sec_data = rb_hash_new();
    rb_hash_aset(sec_data, ID2SYM(rb_intern("index")), INT2FIX(i));
    rb_hash_aset(sec_data, ID2SYM(rb_intern("type")),  rb_str_new2(_dof_sec_type(dof_sec.dofs_type)));
    rb_hash_aset(sec_data, ID2SYM(rb_intern("flags")), INT2FIX(dof_sec.dofs_flags));

    sec = Qnil;
    switch(dof_sec.dofs_type) {
    case DOF_SECT_STRTAB:
      sec = _dof_parse_string_table(self, dof, &dof_sec);
      break;
    case DOF_SECT_PROBES:
      sec = _dof_parse_dof_probe_t_array(self, dof, &dof_sec);
      break;
    case DOF_SECT_PROVIDER:
      sec = _dof_parse_dof_provider_t(self, dof, &dof_sec);
      break;
    case DOF_SECT_PRARGS:
      sec = _dof_parse_uint8_t_array(self, dof, &dof_sec);
      break;
    case DOF_SECT_PRENOFFS:
    case DOF_SECT_PROFFS:
      sec = _dof_parse_uint32_t_array(self, dof, &dof_sec);
      break;
    case DOF_SECT_RELTAB:
      sec = _dof_parse_dof_relodesc_t_array(self, dof, &dof_sec);
      break;
    case DOF_SECT_URELHDR:
      sec = _dof_parse_dof_relohdr_t(self, dof, &dof_sec);
      break;
    case DOF_SECT_UTSNAME:
      sec = _dof_parse_utsname(self, dof, &dof_sec);
      break;      
    case DOF_SECT_COMMENTS:
      sec = _dof_parse_comments(self, dof, &dof_sec);
      break;      
    default:
      sec = _dof_parse_unknown(self, dof, &dof_sec);
      break;
    }
    rb_hash_aset(sec_data, ID2SYM(rb_intern("data")), sec);

    rb_ary_push(dof_data, sec_data);
    pos += dof_hdr.dofh_secsize;
  }

  return dof_data;
}

