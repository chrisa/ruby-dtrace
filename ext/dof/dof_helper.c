/* Ruby-Dtrace
 * (c) 2008 Chris Andrews <chris@nodnol.org>
 */

#include "dof.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>

RUBY_EXTERN VALUE eDtraceDofException;

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

/* Load the given Dtrace::Dof::File into the kernel, against the given
   module name. */
VALUE dof_loaddof(VALUE self, VALUE dof_file, VALUE module_name)
{
  dof_helper_t dh;
  int fd;
  int gen;
  dof_file_t *file;
  dof_hdr_t *dof;

  Data_Get_Struct(dof_file, dof_file_t, file);
  dof = (dof_hdr_t *)file->dof;

  if (dof->dofh_ident[DOF_ID_MAG0] != DOF_MAG_MAG0 ||
      dof->dofh_ident[DOF_ID_MAG1] != DOF_MAG_MAG1 ||
      dof->dofh_ident[DOF_ID_MAG2] != DOF_MAG_MAG2 ||
      dof->dofh_ident[DOF_ID_MAG3] != DOF_MAG_MAG3) {
    rb_raise(eDtraceDofException, "DOF corrupt: bad magic");
    return Qnil;
  }

  dh.dofhp_dof  = (uintptr_t)dof;
  dh.dofhp_addr = (uintptr_t)dof;
  (void) snprintf(dh.dofhp_mod, sizeof (dh.dofhp_mod), RSTRING(module_name)->ptr);

  if ((fd = open(helper, O_RDWR)) < 0) {
    rb_raise(eDtraceDofException, "failed to open helper device %s: %s",
	     helper, strerror(errno));
    return Qnil;
  }
  else {
    if ((gen = _loaddof(fd, &dh)) < 0)
      rb_raise(eDtraceDofException, "DTrace ioctl failed: %s", strerror(errno));

    (void) close(fd);
  }

  return Qnil;
}

