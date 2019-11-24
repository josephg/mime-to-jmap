#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "jmap_mail.h"

#ifdef USE_EMSCRIPTEN
#include <emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

static struct buf warn_out = {};

void log_warning(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    buf_vprintf(&warn_out, fmt, args);
    buf_appendcstr(&warn_out, "\n");
    va_end(args);
}

EMSCRIPTEN_KEEPALIVE
__attribute__((__visibility__("default")))
char *to_jmap(const char *mime_text) {
    struct buf *b = buf_new();
    buf_init_ro(b, mime_text, strlen(mime_text));

    json_t *ret;
    int r = jmap_email_from_buf(b, NULL, &ret);
    if (r) {
        fprintf(stderr, "Error parsing MIME message\n");
        if (buf_len(&warn_out)) {
            fprintf(stderr, "Messages:\n%s\n", buf_cstring(&warn_out));
        }
        return NULL;
    }

    char *j = json_dumps(ret, 0);
    return j;
}

#ifndef USE_EMSCRIPTEN
int main(int argc, char *argv[]) {
    // printf("oh hai\n");

    // log_warning("oh hai");

    // FILE *f = fopen("single.mbox", "r");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s filename.eml\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        fprintf(stderr, "File '%s' not found\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    off_t filelen = ftello(f);
    fseek(f, 0, SEEK_SET);

    char *data = xzmalloc(filelen + 1);
    assert(1 == fread(data, filelen, 1, f));
    data[filelen] = '\0';

    char *j = to_jmap(data);
    if (j == NULL) {
        return 1;
    }

    printf("%s\n", j);
    free(j);

    return 0;
}
#endif


EXPORTED void fatal(const char *s, int code) {
    assert(0);
}