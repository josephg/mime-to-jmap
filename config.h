// #define EXPORTED

#define IMAP_MESSAGE_BADHEADER 1
#define IMAP_INTERNAL 2


#define HAVE_TIMEGM 1
#define HAVE_UNISTD_H
#define HAVE_STDINT_H
#define HAVE_LIBUUID


#define HAVE_VISIBILITY 1

#if HAVE_VISIBILITY
#define EXPORTED __attribute__((__visibility__("default")))
#define HIDDEN   __attribute__((__visibility__("hidden")))
#else
#define EXPORTED
#define HIDDEN
#endif
