/* xmalloc.c -- Allocation package that calls fatal() when out of memory
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"
#undef malloc
#undef free
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#ifndef USE_EMSCRIPTEN
#include <execinfo.h>
#else
#include <emscripten.h>
#endif

#include "xmalloc.h"

#define PRINT_ALLOCATIONS 0

static void print_trace ()
{
#if !defined(USE_EMSCRIPTEN) && LEAK_TRACE
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

//   printf ("Obtained %zd stack frames.\n", size);

  for (i = 1; i < size; i++)
     fprintf (stderr, "%s\n", strings[i]);

  free (strings);
#endif
}

#if LEAK_TRACE
static int trace_enabled = 0;
static size_t numalloc = 0;
static size_t bytealloc = 0;

struct mem_entry {
    size_t size;
    void *ptr;
};
static const int num_entries = 10000;
static int held_used = 0;
struct mem_entry held[num_entries] = {};

static void _rm_at_idx(int idx) {
    held[idx] = held[--held_used];
}
#endif

EMSCRIPTEN_KEEPALIVE
EXPORTED void* xmalloc(size_t size)
{
    void *ret;
#if LEAK_TRACE
    ret = _inst_malloc(size);
#else
    ret = malloc(size);
#endif
    if (ret != NULL) return ret;

    fatal("Virtual memory exhausted", EX_TEMPFAIL);
    return 0; /*NOTREACHED*/
}

EXPORTED void* xzmalloc(size_t size)
{
    void *ret = xmalloc(size);
    memset(ret, 0, size);
    return ret;
}

EXPORTED void *xcalloc(size_t nmemb, size_t size)
{
    return xzmalloc(nmemb * size);
}

EXPORTED void *xrealloc (void* ptr, size_t size)
{
    void *ret;

#if LEAK_TRACE
    /* xrealloc (NULL, size) behaves like xmalloc (size), as in ANSI C */
    // ret = (!ptr ? malloc (size) : realloc (ptr, size));
    if (ptr == NULL) return _inst_malloc(size);
    else {
        void *base = ptr - sizeof(size_t);
        size_t old_size = *(size_t *)base;
        ret = realloc (base, size + sizeof(size_t));
        if (ret == NULL) {
            fatal("Virtual memory exhausted", EX_TEMPFAIL);
            return 0; /*NOTREACHED*/
        }

        if (old_size != SIZE_MAX) {
            bytealloc -= old_size;
        }

        if (trace_enabled) {
            *(size_t *)ret = size;
            bytealloc += size;
            for (int i = 0; i < held_used; i++) {
                if (held[i].ptr == base) {
                    held[i].ptr = ret;
                    held[i].size = size;
                }
            }
#if PRINT_ALLOCATIONS
            fprintf(stderr, "REALLOC(%zd) %p -> %p\n", size, ptr, ret);
#endif
        } else {
            *(size_t *)ret = SIZE_MAX;
        }
        
        return ret + sizeof(size_t);
    }
#else
    ret = (!ptr ? malloc (size) : realloc (ptr, size));
    if (ret != NULL) return ret;
    fatal("Virtual memory exhausted", EX_TEMPFAIL);
    return 0; /*NOTREACHED*/
#endif
}

EXPORTED char *xstrdup(const char* str)
{
    char *p = xmalloc(strlen(str)+1);
    strcpy(p, str);
    return p;
}

/* return a malloced "" if NULL is passed */
EXPORTED char *xstrdupsafe(const char *str)
{
    return str ? xstrdup(str) : xstrdup("");
}

/* return NULL if NULL is passed */
EXPORTED char *xstrdupnull(const char *str)
{
    return str ? xstrdup(str) : NULL;
}

EXPORTED char *xstrndup(const char* str, size_t len)
{
    char *p = xmalloc(len+1);
    if (len) strncpy(p, str, len);
    p[len] = '\0';
    return p;
}

EXPORTED void *xmemdup(const void *ptr, size_t size)
{
    void *p = xmalloc(size);
    memcpy(p, ptr, size);
    return p;
}

#if LEAK_TRACE
void *_inst_malloc(size_t size) {
    // size_t *ptr = (size_t *)malloc(size + sizeof(size_t));

    void *ptr = malloc(size + sizeof(size_t));
    if (trace_enabled) {
        *(size_t *)ptr = size;
        held[held_used++] = (struct mem_entry){size, ptr};
        numalloc++;
        bytealloc += size;
#if PRINT_ALLOCATIONS
        fprintf(stderr, "ALLOC(%ld) %zd %zd -> %p\n", size, numalloc, bytealloc, ptr);
        // fprintf(stderr, "ALLOC(%ld) %zd %zd\n", size, numalloc, bytealloc);
        print_trace();
#endif
    } else {
        *(size_t *)ptr = SIZE_MAX;
    }

    // if (ptr == 0x698a10) __builtin_trap();
    return ptr + sizeof(size_t);
}

void _inst_free(void *ptr) {
    if (ptr == NULL) return;

    ptr -= sizeof(size_t);
    size_t size = *(size_t *)ptr;

    if (size != SIZE_MAX) {
        for (int i = 0; i < held_used; i++) {
            if (held[i].ptr == ptr) _rm_at_idx(i);
        }

#if PRINT_ALLOCATIONS
        fprintf(stderr, "FREE(%ld) %zd %zd %p -> %ld\n", size, numalloc, bytealloc, ptr, bytealloc - size);
        // fprintf(stderr, "FREE(%ld) %zd %zd -> %ld\n", size, numalloc, bytealloc, bytealloc - size);
#endif
        free(ptr);
        // print_trace();

        numalloc--;
        bytealloc -= size;
    }
}

void *_raw_malloc(size_t size) { return malloc(size); }
void _raw_free(void *ptr) { free(ptr); }

#endif

EMSCRIPTEN_KEEPALIVE
void start_leaktrace() {
#if LEAK_TRACE
    trace_enabled = 1;
#endif
}


EMSCRIPTEN_KEEPALIVE
int end_leaktrace_and_check() {
#if LEAK_TRACE
    trace_enabled = 0;
    if (bytealloc || numalloc) {
        fprintf(stderr, "MEMORY LEAK DETECTED %ld bytes in %ld ranges\n", bytealloc, numalloc);
        fprintf(stderr, "leaked zones %d\n", held_used);

        for (int i = 0; i < held_used; i++) {
            fprintf(stderr, "leaked %zd %p\n", held[i].size, held[i].ptr);
        }

        return 1;
    } else return 0;
    // assert(bytealloc == 0);
    // assert(numalloc == 0);
#else
    return 0;
#endif
}
