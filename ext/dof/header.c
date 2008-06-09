/* 
 * Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"
#include <errno.h>
#include <string.h>

RUBY_EXTERN eDtraceDofException;

VALUE dof_generate_header(VALUE self) {
  dof_hdr_t hdr;
  uint32_t secnum;
  uint64_t loadsz;
  uint64_t filesz;
  uint64_t hdrlen;
  VALUE hdr_data;
  uint8_t dof_version;

  /* DOF versioning: Apple always needs version 3, but Solaris can use
     1 or 2 depending on whether is-enabled probes are needed. */
#ifdef __APPLE__
  dof_version = DOF_VERSION_3;
#else
  switch(FIX2INT(rb_iv_get(self, "@dof_version"))) {
  case 1:
    dof_version = DOF_VERSION_1;
    break;
  case 2:
    dof_version = DOF_VERSION_2;
    break;
  default:
    dof_version = DOF_VERSION;
  }
#endif
  
  memset(&hdr, 0, sizeof(hdr));
  
  hdr.dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
  hdr.dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
  hdr.dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
  hdr.dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

  hdr.dofh_ident[DOF_ID_MODEL]    = DOF_MODEL_NATIVE;
  hdr.dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
  hdr.dofh_ident[DOF_ID_VERSION]  = dof_version;
  hdr.dofh_ident[DOF_ID_DIFVERS]  = DIF_VERSION;
  hdr.dofh_ident[DOF_ID_DIFIREG]  = DIF_DIR_NREGS;
  hdr.dofh_ident[DOF_ID_DIFTREG]  = DIF_DTR_NREGS;
  
  hdr.dofh_hdrsize = sizeof(dof_hdr_t);
  hdr.dofh_secsize = sizeof(dof_sec_t);
  
  secnum = FIX2INT(rb_iv_get(self, "@secnum"));
  hdr.dofh_secnum = secnum;

  loadsz = FIX2INT(rb_iv_get(self, "@loadsz"));
  filesz = FIX2INT(rb_iv_get(self, "@filesz"));
  
  hdrlen = (sizeof(dof_hdr_t) + secnum * sizeof(dof_sec_t));
  rb_iv_set(self, "@hdrlen", INT2FIX(hdrlen));

  hdr.dofh_loadsz = loadsz + hdrlen;
  hdr.dofh_filesz = filesz + hdrlen;
  hdr.dofh_secoff = sizeof(dof_hdr_t);

  hdr_data = rb_str_new((const char *)&hdr, sizeof(hdr));
  return hdr_data;
}

VALUE dof_header_len(VALUE self) {
  uint64_t hdrlen;
  uint32_t secnum;

  secnum = FIX2INT(rb_iv_get(self, "@secnum"));
  hdrlen = (sizeof(dof_hdr_t) + secnum * sizeof(dof_sec_t));
  
  return INT2FIX(hdrlen);
}
