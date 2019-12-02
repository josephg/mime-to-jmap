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

// int cyrusmsg_from_buf(const struct buf *buf, struct cyrusmsg **msg);
// void cyrusmsg_fini(struct cyrusmsg **msgptr);

// int jmap_json_from_cyrusmsg(struct cyrusmsg *msg, json_t **jsonOut);
// int get_attachments_count(struct cyrusmsg *msg);
// struct buf get_attachment_nth(struct cyrusmsg *msg, int i);


EMSCRIPTEN_KEEPALIVE
__attribute__((__visibility__("default")))
struct cyrusmsg *msg_parse(const char *mime_text, size_t len) {
    // struct buf *b = buf_new();
    struct buf b;
    // fwrite(mime_text, len, 1, stderr);

    buf_init_ro(&b, mime_text, len);

    struct cyrusmsg *ret;
    int r = cyrusmsg_from_buf(&b, &ret);
    buf_free(&b);

    if (r) {
        fprintf(stderr, "Error parsing MIME message %d\n", r);
        if (buf_len(&warn_out)) {
            fprintf(stderr, "Messages:\n%s\n", buf_cstring(&warn_out));
            buf_reset(&warn_out);
        }
        return NULL;
    } else {
        return ret;
    }

    // char *j = json_dumps(ret, 0);
    // return j;
}

EMSCRIPTEN_KEEPALIVE
void msg_free(struct cyrusmsg *msg) {
    cyrusmsg_fini(&msg);
}

EMSCRIPTEN_KEEPALIVE
char *msg_to_json(struct cyrusmsg *msg) {
    json_t *jsonOut;
    int r = jmap_json_from_cyrusmsg(msg, &jsonOut);
    if (r) {
        fprintf(stderr, "Error parsing MIME message to JSON %d\n", r);
        if (buf_len(&warn_out)) {
            fprintf(stderr, "Messages:\n%s\n", buf_cstring(&warn_out));
            buf_reset(&warn_out);
        }
        return NULL;
    } else {
        char *ret = json_dumps(jsonOut, JSON_COMPACT | JSON_SORT_KEYS);
        json_delete(jsonOut);
        return ret;
    }
}


EMSCRIPTEN_KEEPALIVE
char *get_blob_space() {
    static char blobSpace[42] = {};
    return blobSpace;
}

// The blobid should always be a 42 byte long string pulled out of the JSON,
// including \0.
EMSCRIPTEN_KEEPALIVE
const char *msg_get_blob(struct cyrusmsg *msg, char *blobId, size_t expectedSize) {
    return get_attachment_with_blobid(msg, blobId == NULL ? get_blob_space() : blobId, expectedSize);
}

#ifndef USE_EMSCRIPTEN
int main(int argc, char *argv[]) {
    // getchar();

    // log_warning("oh hai");

    // FILE *f = fopen("single.mbox", "r");

    // if (argc < 2) {
    //     fprintf(stderr, "Usage: %s filename.eml\n", argv[0]);
    //     return 1;
    // }
    FILE *f;
    struct buf buf = {};

    if (argc >= 2) {
        // Read from file
        f = fopen(argv[1], "r");
        if (f == NULL) {
            fprintf(stderr, "File '%s' not found\n", argv[1]);
            return 1;
        }
    } else {
        f = stdin;
    }
        
    size_t num_read;
    do {
        char chars[1024];
        num_read = fread(chars, 1, 1024, f);
        buf_appendmap(&buf, chars, num_read);
        if (num_read < 1024) break;
    } while (num_read == 1024);

    struct cyrusmsg *msg = msg_parse(buf_base(&buf), buf_len(&buf));
    buf_free(&buf);
    if (msg == NULL) return 1;

    char *json = msg_to_json(msg);
    if (json == NULL) return 1;
    printf("%s\n", json);
    free(json);

    for (int i = 0; i < msg_get_attachments_count(msg); i++) {
        fprintf(stderr, "Attachment %s length %zd\n",
            msg_get_attachment_blobid(msg, i),
            msg_get_attachment_nth_len(msg, i)
        );
    }

    msg_free(msg);

    // getchar();
    return 0;
}
#endif


EXPORTED void fatal(const char *s, int code) {
    assert(0);
}