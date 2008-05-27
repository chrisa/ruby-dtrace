/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

VALUE cDtraceDofParser;
VALUE cDtraceDofGenerator;
VALUE cDtraceDofSection;
VALUE cDtraceDofHeader;
VALUE eDtraceDofException;

void Init_dof_api() {
  VALUE dtrace = rb_define_class("Dtrace", rb_cObject);
  VALUE dof    = rb_define_class_under(dtrace, "Dof", rb_cObject);
  
  eDtraceDofException = rb_define_class_under(dof, "Exception", rb_eStandardError);

  cDtraceDofParser    = rb_define_class_under(dof, "Parser",    rb_cObject);
  cDtraceDofGenerator = rb_define_class_under(dof, "Generator", rb_cObject);

  rb_define_singleton_method(cDtraceDofParser, "parse", dof_parse, 1); // in parser.c

  cDtraceDofSection = rb_define_class_under(dof, "Section", rb_cObject);
  rb_define_method(cDtraceDofSection, "dof_generate_comments",  dof_generate_comments,  0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_probes",    dof_generate_probes,    0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_strtab",    dof_generate_strtab,    0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_utsname",   dof_generate_utsname,   0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_prargs",    dof_generate_prargs,    0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_proffs",    dof_generate_proffs,    0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_prenoffs",  dof_generate_prenoffs,  0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_provider",  dof_generate_provider,  0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_reltab",    dof_generate_reltab,    0); // in section.c
  rb_define_method(cDtraceDofSection, "dof_generate_relhdr",    dof_generate_relhdr,    0); // in section.c
  rb_define_method(cDtraceDofSection, "generate_header",        dof_generate_section_header, 0); // in section.c

  cDtraceDofHeader = rb_define_class_under(dof, "Header", rb_cObject);
  rb_define_attr(cDtraceDofHeader, "loadsz", 1, 1);
  rb_define_attr(cDtraceDofHeader, "filesz", 1, 1);
  rb_define_attr(cDtraceDofHeader, "secnum", 1, 1);
  rb_define_attr(cDtraceDofHeader, "hdrlen", 1, 0);
  rb_define_attr(cDtraceDofHeader, "dof_version", 0, 1);
  rb_define_method(cDtraceDofHeader, "generate", dof_generate_header, 0); // in header.c
  rb_define_method(cDtraceDofHeader, "hdrlen",   dof_header_len,      0); // in header.c

  _init_constants(dof);
}
