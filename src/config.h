#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <time.h>

#define TIME_HAS_GMTOFF 1

#define IMAP_MESSAGE_BADHEADER 1
#define IMAP_INTERNAL 2
#define IMAP_IOERROR 3
#define IMAP_MESSAGE_CONTAINSNULL 4
#define IMAP_MESSAGE_CONTAINSNL 5
#define IMAP_MESSAGE_CONTAINS8BIT 6
#define IMAP_NOTFOUND 7
// #define EX_OSFILE 3
// #define EX_SOFTWARE 4

// 64 bit
// #define SIZE_T_FMT "%lu"
#define SIZE_T_FMT "%zu"

#define HAVE_TIMEGM 1
#define HAVE_UNISTD_H
#define HAVE_STDINT_H
#define HAVE_LIBUUID

// Macos
#define HAVE_STRLCPY 1

#define HAVE_VISIBILITY 1

#if HAVE_VISIBILITY
// Ignore the EXPORTED macro since we don't care
#define EXPORTED //__attribute__((__visibility__("default")))
#define HIDDEN   __attribute__((__visibility__("hidden")))
#else
#define EXPORTED
#define HIDDEN
#endif

#define WITH_DAV 1

// #define MAX_USER_FLAGS (16*8)
// #define MAX_USER_FLAGS 0

void log_warning(const char *fmt, ...);

#endif