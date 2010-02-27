#ifndef MCED_UTIL_H__
#define MCED_UTIL_H__

/*
 * Read a whole line from 'fd'.  Return a pointer to a static buffer
 * holding the data.  The buffer will be reused and/or realloc()ed on
 * subsequent calls to this function.  If you need to persist the data you
 * must make a copy of it.
 *
 * In case of error, return NULL and set errno.  In case of EOF, set errno
 * to EPIPE.
 */
extern char *read_line(int fd);

#endif  /* MCED_UTIL_H__ */
