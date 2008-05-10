/* Ruby-Dtrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>

RUBY_EXTERN VALUE eDtraceException;

/* ignore Sol10 GA ... */
#ifdef __APPLE__
static const char *helper = "/dev/dtracehelper";
#else
static const char *helper = "/dev/dtrace/helper";
#endif

VALUE dtracehelper_loaddof(VALUE self, VALUE rdof)
{
  dof_hdr_t *dof = NULL;
  dof_helper_t dh;
  int fd;
  int gen;

  dof = (dof_hdr_t *)RSTRING(rdof)->ptr;

  if (dof->dofh_ident[DOF_ID_MAG0] != DOF_MAG_MAG0 ||
      dof->dofh_ident[DOF_ID_MAG1] != DOF_MAG_MAG1 ||
      dof->dofh_ident[DOF_ID_MAG2] != DOF_MAG_MAG2 ||
      dof->dofh_ident[DOF_ID_MAG3] != DOF_MAG_MAG3) {
    rb_raise(eDtraceException, "DOF corrupt: bad magic");
    return Qnil;
  }

  dh.dofhp_dof  = (uintptr_t)dof;
  dh.dofhp_addr = (uintptr_t)dof;
  
  (void) snprintf(dh.dofhp_mod, sizeof (dh.dofhp_mod), "testmodule");

  if ((fd = open(helper, O_RDWR)) < 0) {
    rb_raise(eDtraceException, "failed to open helper device %s: %s", 
	     helper, strerror(errno));
    return Qnil;
  }
  else {
    if ((gen = ioctl(fd, DTRACEHIOC_ADDDOF, &dh)) < 0)
      rb_raise(eDtraceException, "DTrace ioctl failed: %s", strerror(errno));
    
    (void) close(fd);
  }

  return Qnil;
}
  
