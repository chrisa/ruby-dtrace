/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>

RUBY_EXTERN VALUE eDtraceException;

#ifdef __APPLE__
static const char *helper = "/dev/dtracehelper";

int _loaddof(int fd, dof_helper_t *dh)
{
  int ret;
  uint8_t buffer[sizeof(dof_ioctl_data_t) + sizeof(dof_helper_t)];
  dof_ioctl_data_t* ioctlData = (dof_ioctl_data_t*)buffer;

  ioctlData->dofiod_count = 1LL;
  memcpy(&ioctlData->dofiod_helpers[0], dh, sizeof(dof_helper_t));

  user_addr_t val = (user_addr_t)(unsigned long)ioctlData;
  ret = ioctl(fd, DTRACEHIOC_ADDDOF, &val);
  
  return ret;
}

#else /* Solaris */

/* ignore Sol10 GA ... */
static const char *helper = "/dev/dtrace/helper";

int _loaddof(int fd, dof_helper_t *dh)
{
  return ioctl(fd, DTRACEHIOC_ADDDOF, dh);
}

#endif

VALUE dtracehelper_loaddof(VALUE self, VALUE rdof, VALUE module_name)
{
  dof_hdr_t *dof = NULL;
  dof_helper_t dh;
  int fd;
  int gen;

  dof = (dof_hdr_t *)ALLOC_N(char, RSTRING(rdof)->len);
  memcpy(dof, RSTRING(rdof)->ptr, RSTRING(rdof)->len);

  if (dof->dofh_ident[DOF_ID_MAG0] != DOF_MAG_MAG0 ||
      dof->dofh_ident[DOF_ID_MAG1] != DOF_MAG_MAG1 ||
      dof->dofh_ident[DOF_ID_MAG2] != DOF_MAG_MAG2 ||
      dof->dofh_ident[DOF_ID_MAG3] != DOF_MAG_MAG3) {
    rb_raise(eDtraceException, "DOF corrupt: bad magic");
    return Qnil;
  }

  dh.dofhp_dof  = (uintptr_t)dof;
  dh.dofhp_addr = (uintptr_t)dof;
  (void) snprintf(dh.dofhp_mod, sizeof (dh.dofhp_mod), RSTRING(module_name)->ptr);

  if ((fd = open(helper, O_RDWR)) < 0) {
    rb_raise(eDtraceException, "failed to open helper device %s: %s", 
	     helper, strerror(errno));
    return Qnil;
  }
  else {
    if ((gen = _loaddof(fd, &dh)) < 0)
      rb_raise(eDtraceException, "DTrace ioctl failed: %s", strerror(errno));

    (void) close(fd);
  }

  return Qnil;
}
  
