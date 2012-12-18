/* Ruby-DTrace
 * (c) 2007 Chris Andrews <chris@nodnol.org>
 */

#include "dtrace_api.h"
#include <ctype.h>

RUBY_EXTERN VALUE eDTraceException;

/*
 * Most of this function lifted from libdtrace/common/dt_consume.c
 * dt_print_bytes().
 */
VALUE handle_bytedata(caddr_t addr, uint32_t nbytes)
{
  /*
   * If the byte stream is a series of printable characters, followed by
   * a terminating byte, we print it out as a string.  Otherwise, we
   * assume that it's something else and just print the bytes.
   */
  int i, j;
  char *c = addr;

  VALUE robj;

  if (nbytes == 0) {
    return rb_str_new2("");
  }

  for (i = 0; i < nbytes; i++) {
    /*
     * We define a "printable character" to be one for which
     * isprint(3C) returns non-zero, isspace(3C) returns non-zero,
     * or a character which is either backspace or the bell.
     * Backspace and the bell are regrettably special because
     * they fail the first two tests -- and yet they are entirely
     * printable.  These are the only two control characters that
     * have meaning for the terminal and for which isprint(3C) and
     * isspace(3C) return 0.
     */
    if (isprint(c[i]) || isspace(c[i]) ||
	c[i] == '\b' || c[i] == '\a')
      continue;

    if (c[i] == '\0' && i > 0) {
      /*
       * This looks like it might be a string.  Before we
       * assume that it is indeed a string, check the
       * remainder of the byte range; if it contains
       * additional non-nul characters, we'll assume that
       * it's a binary stream that just happens to look like
       * a string.
       */
      for (j = i + 1; j < nbytes; j++) {
	if (c[j] != '\0')
	  break;
      }

      if (j != nbytes)
	break;

      /* It's a string */
      return (rb_str_new2((char *)addr));
    }

    break;
  }

  if (i == nbytes) {
    /*
     * The byte range is all printable characters, but there is
     * no trailing nul byte.  We'll assume that it's a string.
     */
    char *s = malloc(nbytes + 1);
    if (!s) {
      rb_raise(eDTraceException, "out of memory: failed to allocate string value");
      return (Qnil);
    }
    (void) strncpy(s, c, nbytes);
    s[nbytes] = '\0';
    robj = rb_str_new2(s);
    free(s);
    return (robj);
  }

  /* return byte array */
  robj = rb_ary_new();
  for (i = 0; i < nbytes; i++)
    rb_ary_push(robj, INT2FIX(addr[i]));

  return (robj);
}  
