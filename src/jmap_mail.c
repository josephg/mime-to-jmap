// /* jmap_mail.c -- Routines for handling JMAP mail messages
//  *
//  * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
//  *
//  * Redistribution and use in source and binary forms, with or without
//  * modification, are permitted provided that the following conditions
//  * are met:
//  *
//  * 1. Redistributions of source code must retain the above copyright
//  *    notice, this list of conditions and the following disclaimer.
//  *
//  * 2. Redistributions in binary form must reproduce the above copyright
//  *    notice, this list of conditions and the following disclaimer in
//  *    the documentation and/or other materials provided with the
//  *    distribution.
//  *
//  * 3. The name "Carnegie Mellon University" must not be used to
//  *    endorse or promote products derived from this software without
//  *    prior written permission. For permission or any legal
//  *    details, please contact
//  *      Carnegie Mellon University
//  *      Center for Technology Transfer and Enterprise Creation
//  *      4615 Forbes Avenue
//  *      Suite 302
//  *      Pittsburgh, PA  15213
//  *      (412) 268-7393, fax: (412) 268-7395
//  *      innovation@andrew.cmu.edu
//  *
//  * 4. Redistributions of any form whatsoever must retain the following
//  *    acknowledgment:
//  *    "This product includes software developed by Computing Services
//  *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
//  *
//  * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
//  * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
//  * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
//  * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
//  * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
//  * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//  *
//  */

// // This has been modified by Seph Gentle 2019.

// #ifdef HAVE_UNISTD_H
// #include <unistd.h>
// #endif
// #include <ctype.h>
// #include <string.h>
// #include <syslog.h>
#include <assert.h>
// #include <sys/mman.h>

// // #include <sasl/saslutil.h>

// // #ifdef HAVE_LIBCHARDET
// // #include <chardet/chardet.h>
// // #endif

typedef void* jmap_req_t;

#include "jmap_api.h"
#include "jmap_util.h"
#include "charset.h"
#include "hash.h"
#include "ptrarray.h"
#include "message.h"
// // #include "acl.h"
// // #include "annotate.h"
// // #include "append.h"
// // #include "bsearch.h"
// // #include "carddav_db.h"
// // #include "hashset.h"
// // #include "http_dav.h"
// // #include "http_jmap.h"
// // #include "http_proxy.h"
// // #include "jmap_ical.h"
#include "jmap_mail.h"
#include "jmap_mail_query.h"
// // #include "json_support.h"
// // #include "mailbox.h"
// // #include "mappedfile.h"
// // #include "mboxevent.h"
// // #include "mboxlist.h"
// // #include "mboxname.h"
#include "msgrecord.h"
// // #include "notify.h"
#include "parseaddr.h"
#include "prot.h"
// // #include "proxy.h"
// // #include "search_query.h"
// // #include "seen.h"
// // #include "smtpclient.h"
// // #include "statuscache.h"
// // #include "stristr.h"
// // #include "sync_log.h"
#include "times.h"
// // #include "util.h"
#include "xmalloc.h"
// // #include "xsha1.h"
// // #include "xstrnchr.h"

#define JMAP_HAS_ATTACHMENT_FLAG "$HasAttachment"

typedef enum MsgType {
        MSG_IS_ROOT = 0,
        MSG_IS_ATTACHED = 1,
} MsgType;

/*
 * Emails
 */

static char *_decode_to_utf8(const char *charset,
                             const char *data, size_t datalen,
                             const char *encoding,
                             int *is_encoding_problem)
{
    charset_t cs = charset_lookupname(charset);
    char *text = NULL;
    int enc = encoding_lookupname(encoding);

    if (cs == CHARSET_UNKNOWN_CHARSET || enc == ENCODING_UNKNOWN) {
        log_warning("decode_to_utf8 error (%s, %s)", charset, encoding);
        *is_encoding_problem = 1;
        goto done;
    }
    text = charset_to_utf8(data, datalen, cs, enc);
    if (!text) {
        *is_encoding_problem = 1;
        goto done;
    }

    size_t textlen = strlen(text);
    struct char_counts counts = charset_count_validutf8(text, textlen);
    *is_encoding_problem = counts.invalid || counts.replacement;

    const char *charset_id = charset_name(cs);
    if (!strncasecmp(charset_id, "UTF-32", 6)) {
        /* Special-handle UTF-32. Some clients announce the wrong endianess. */
        if (counts.invalid || counts.replacement) {
            charset_t guess_cs = CHARSET_UNKNOWN_CHARSET;
            if (!strcasecmp(charset_id, "UTF-32") || !strcasecmp(charset_id, "UTF-32BE"))
                guess_cs = charset_lookupname("UTF-32LE");
            else
                guess_cs = charset_lookupname("UTF-32BE");
            char *guess = charset_to_utf8(data, datalen, guess_cs, enc);
            if (guess) {
                struct char_counts guess_counts = charset_count_validutf8(guess, strlen(guess));
                if (guess_counts.valid > counts.valid) {
                    free(text);
                    text = guess;
                    counts = guess_counts;
                }
            }
            charset_free(&guess_cs);
        }
    }

#ifdef HAVE_LIBCHARDET
    if (counts.invalid || counts.replacement) {
        static Detect *d = NULL;
        if (!d) d = detect_init();

        DetectObj *obj = detect_obj_init();
        if (!obj) goto done;
        detect_reset(&d);

        struct buf buf = BUF_INITIALIZER;
        charset_decode(&buf, data, datalen, enc);
        buf_cstring(&buf);
        if (detect_handledata_r(&d, buf_base(&buf), buf_len(&buf), &obj) == CHARDET_SUCCESS) {
            charset_t guess_cs = charset_lookupname(obj->encoding);
            if (guess_cs != CHARSET_UNKNOWN_CHARSET) {
                char *guess = charset_to_utf8(data, datalen, guess_cs, enc);
                if (guess) {
                    struct char_counts guess_counts = charset_count_validutf8(guess, strlen(guess));
                    if (guess_counts.valid > counts.valid) {
                        free(text);
                        text = guess;
                        counts = guess_counts;
                    }
                    else {
                        free(guess);
                    }
                }
                charset_free(&guess_cs);
            }
        }
        detect_obj_free(&obj);
        buf_free(&buf);
    }
#endif

done:
    charset_free(&cs);
    return text;
}

static char *_decode_mimeheader(const char *raw)
{
    if (!raw) return NULL;

    int is_8bit = 0;
    const char *p;
    for (p = raw; *p; p++) {
        if (*p & 0x80) {
            is_8bit = 1;
            break;
        }
    }

    char *val = NULL;
    if (is_8bit) {
        int err = 0;
        val = _decode_to_utf8("utf-8", raw, strlen(raw), NULL, &err);
    }
    if (!val) {
        val = charset_decode_mimeheader(raw, CHARSET_KEEPCASE);
    }
    return val;
}

struct headers {
    json_t *raw; /* JSON array of EmailHeader */
    json_t *all; /* JSON object: lower-case header name => list of values */
    struct buf buf;
};

#define HEADERS_INITIALIZER \
    { json_array(), json_object(), BUF_INITIALIZER }

static void _headers_init(struct headers *headers) {
    headers->raw = json_array();
    headers->all = json_object();
    memset(&headers->buf, 0, sizeof(struct buf));
}

static void _headers_fini(struct headers *headers) {
    json_decref(headers->all);
    json_decref(headers->raw);
    buf_free(&headers->buf);
}

static void _headers_put_new(struct headers *headers, json_t *header, int shift)
{
    const char *name = json_string_value(json_object_get(header, "name"));

    if (headers->raw == NULL)
        headers->raw = json_array();
    if (headers->all == NULL)
        headers->all = json_object();

    /* Append (or shift) the raw header to the in-order header list */
    if (shift)
        json_array_insert(headers->raw, 0, header);
    else
        json_array_append(headers->raw, header);

    /* Append the raw header to the list of all equal-named headers */
    buf_setcstr(&headers->buf, name);
    const char *lcasename = buf_lcase(&headers->buf);
    json_t *all = json_object_get(headers->all, lcasename);
    if (!all) {
        all = json_array();
        json_object_set_new(headers->all, lcasename, all);
    }

    if (shift)
        json_array_insert_new(all, 0, header);
    else
        json_array_append_new(all, header);
}

static void _headers_add_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 0);
}

static void _headers_shift_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 1);
}

static json_t* _headers_get(struct headers *headers, const char *name)
{
    char *lcasename = lcase(xstrdup(name));
    json_t *jheader = json_object_get(headers->all, lcasename);
    free(lcasename);
    return jheader;
}

static int _headers_have(struct headers *headers, const char *name)
{
    return _headers_get(headers, name) != NULL;
}

static int _headers_from_mime_cb(const char *key, const char *val, void *_rock)
{
    struct headers *headers = _rock;
    _headers_add_new(headers, json_pack("{s:s s:s}", "name", key, "value", val));
    return 0;
}

static void _headers_from_mime(const char *base, size_t len, struct headers *headers)
{
    message_foreach_header(base, len, _headers_from_mime_cb, headers);
}

static json_t *_header_as_raw(const char *raw)
{
    if (!raw) return json_null();
    size_t len = strlen(raw);
    if (len > 1 && raw[len-1] == '\n' && raw[len-2] == '\r') len -= 2;
    return json_stringn(raw, len);
}

static json_t *_header_as_date(const char *raw)
{
    if (!raw) return json_null();

    time_t t;
    if (time_from_rfc5322(raw, &t, DATETIME_FULL) == -1) {
        if (!strchr(raw, '\r')) return json_null();
        char *tmp = charset_unfold(raw, strlen(raw), CHARSET_UNFOLD_SKIPWS);
        int r = time_from_rfc5322(tmp, &t, DATETIME_FULL);
        free(tmp);
        if (r == -1) return json_null();
    }

    char cbuf[RFC3339_DATETIME_MAX+1];
    cbuf[RFC3339_DATETIME_MAX] = '\0';
    time_to_rfc3339(t, cbuf, RFC3339_DATETIME_MAX+1);
    return json_string(cbuf);
}

static json_t *_header_as_text(const char *raw)
{
    if (!raw) return json_null();

    /* TODO this could be optimised to omit unfolding, decoding
     * or normalisation, or all, if ASCII */
    /* Unfold and remove CRLF */
    char *unfolded = charset_unfold(raw, strlen(raw), 0);
    char *p = strchr(unfolded, '\r');
    while (p && *(p + 1) != '\n') {
        p = strchr(p + 1, '\r');
    }
    if (p) *p = '\0';

    /* Trim starting SP */
    const char *trimmed = unfolded;
    while (isspace(*trimmed)) {
        trimmed++;
    }

    /* Decode header */
    char *decoded = _decode_mimeheader(trimmed);

    /* Convert to Unicode NFC */
    char *normalized = charset_utf8_normalize(decoded);

    json_t *result = json_string(normalized);
    free(normalized);
    free(decoded);
    free(unfolded);
    return result;
}

static void _remove_ws(char *s)
{
    char *d = s;
    do {
        while (isspace(*s))
            s++;
    } while ((*d++ = *s++));
}

static json_t *_header_as_messageids(const char *raw)
{
    if (!raw) return json_null();
    json_t *msgids = json_array();
    char *unfolded = charset_unfold(raw, strlen(raw), CHARSET_UNFOLD_SKIPWS);

    const char *p = unfolded;

    while (*p) {
        /* Skip preamble */
        while (isspace(*p) || *p == ',') p++;
        if (!*p) break;

        /* Find end of id */
        const char *q = p;
        if (*p == '<') {
            while (*q && *q != '>') q++;
        }
        else {
            while (*q && !isspace(*q)) q++;
        }

        /* Read id */
        char *val = xstrndup(*p == '<' ? p + 1 : p,
                             *q == '>' ? q - p - 1 : q - p);
        if (*p == '<') {
            _remove_ws(val);
        }
        if (*val) {
            /* calculate the value that would be created if this was
             * fed back into an Email/set and make sure it would
             * validate */
            char *msgid = strconcat("<", val, ">", NULL);
            // int r = conversations_check_msgid(msgid, strlen(msgid));
            // if (!r) json_array_append_new(msgids, json_string(val));
            json_array_append_new(msgids, json_string(val)); // EDITED - not checking msgid
            free(msgid);
        }
        free(val);

        /* Reset iterator */
        p = *q ? q + 1 : q;
    }


    if (!json_array_size(msgids)) {
        json_decref(msgids);
        msgids = json_null();
    }
    free(unfolded);
    return msgids;
}

static json_t *_emailaddresses_from_addr(struct address *addr)
{
    if (!addr) return json_null();

    json_t *addresses = json_array();
    struct buf buf = BUF_INITIALIZER;

    while (addr) {
        json_t *e = json_pack("{}");

        const char *domain = addr->domain;
        if (!strcmpsafe(domain, "unspecified-domain")) {
            domain = NULL;
        }

        if (!addr->name && addr->mailbox && !domain) {
            /* That's a group */
            json_object_set_new(e, "name", json_string(addr->mailbox));
            json_object_set_new(e, "email", json_null());
            json_array_append_new(addresses, e);
            addr = addr->next;
            continue;
        }

        /* name */
        if (addr->name) {
            char *tmp = _decode_mimeheader(addr->name);
            if (tmp) json_object_set_new(e, "name", json_string(tmp));
            free(tmp);
        } else {
            json_object_set_new(e, "name", json_null());
        }

        /* email */
        if (addr->mailbox) {
            buf_setcstr(&buf, addr->mailbox);
            if (domain) {
                buf_putc(&buf, '@');
                buf_appendcstr(&buf, domain);
            }
            json_object_set_new(e, "email", json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        } else {
            json_object_set_new(e, "email", json_null());
        }
        json_array_append_new(addresses, e);
        addr = addr->next;
    }

    if (!json_array_size(addresses)) {
        json_decref(addresses);
        addresses = json_null();
    }
    buf_free(&buf);
    return addresses;
}


static json_t *_header_as_addresses(const char *raw)
{
    if (!raw) return json_null();

    struct address *addrs = NULL;
    parseaddr_list(raw, &addrs);
    json_t *result = _emailaddresses_from_addr(addrs);
    parseaddr_free(addrs);
    return result;
}

static json_t *_header_as_urls(const char *raw)
{
    if (!raw) return json_null();

    /* A poor man's implementation of RFC 2369, returning anything
     * between < and >. */
    json_t *urls = json_array();
    const char *base = raw;
    const char *top = raw + strlen(raw);
    while (base < top) {
        const char *lo = strchr(base, '<');
        if (!lo) break;
        const char *hi = strchr(lo, '>');
        if (!hi) break;
        char *tmp = charset_unfold(lo + 1, hi - lo - 1, CHARSET_UNFOLD_SKIPWS);
        _remove_ws(tmp);
        if (*tmp) json_array_append_new(urls, json_string(tmp));
        free(tmp);
        base = hi + 1;
    }
    if (!json_array_size(urls)) {
        json_decref(urls);
        urls = json_null();
    }
    return urls;
}

enum _header_form {
    HEADER_FORM_UNKNOWN = 0, /* MUST be zero so we can cast to void* */
    HEADER_FORM_RAW,
    HEADER_FORM_TEXT,
    HEADER_FORM_ADDRESSES,
    HEADER_FORM_MESSAGEIDS,
    HEADER_FORM_DATE,
    HEADER_FORM_URLS
};

struct header_prop {
    char *lcasename;
    char *name;
    const char *prop;
    enum _header_form form;
    int all;
};

static void _header_prop_fini(struct header_prop *prop)
{
    free(prop->lcasename);
    free(prop->name);
}

static void _header_prop_free(struct header_prop *prop)
{
    _header_prop_fini(prop);
    free(prop);
}

static struct header_prop *_header_parseprop(const char *s)
{
    strarray_t *fields = strarray_split(s + 7, ":", 0);
    const char *f0, *f1, *f2;
    int is_valid = 1;
    enum _header_form form = HEADER_FORM_RAW;
    char *lcasename = NULL, *name = NULL;

    /* Initialize allowed header forms by lower-case header name. Any
     * header in this map is allowed to be requested either as Raw
     * or the form of the map value (casted to void* because C...).
     * Any header not found in this map is allowed to be requested
     * in any form. */
    static hash_table allowed_header_forms = HASH_TABLE_INITIALIZER;
    if (allowed_header_forms.size == 0) {
        /* TODO initialize with all headers in RFC5322 and RFC2369 */
        construct_hash_table(&allowed_header_forms, 32, 0);
        hash_insert("bcc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("cc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("content-type", (void*) HEADER_FORM_RAW, &allowed_header_forms);
        hash_insert("comment", (void*) HEADER_FORM_TEXT, &allowed_header_forms);
        hash_insert("date", (void*) HEADER_FORM_DATE, &allowed_header_forms);
        hash_insert("from", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("in-reply-to", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("list-archive", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-help", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-owner", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-post", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-subscribe", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-unsubscribe", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("message-id", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("references", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("reply-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-date", (void*) HEADER_FORM_DATE, &allowed_header_forms);
        hash_insert("resent-from", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-message-id", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("resent-reply-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-sender", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-cc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-bcc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("sender", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("subject", (void*) HEADER_FORM_TEXT, &allowed_header_forms);
        hash_insert("to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
    }

    /* Parse property string into fields */
    f0 = f1 = f2 = NULL;
    switch (fields->count) {
        case 3:
            f2 = strarray_nth(fields, 2);
            /* fallthrough */
        case 2:
            f1 = strarray_nth(fields, 1);
            /* fallthrough */
        case 1:
            f0 = strarray_nth(fields, 0);
            lcasename = lcase(xstrdup(f0));
            name = xstrdup(f0);
            break;
        default:
            strarray_free(fields);
            return NULL;
    }

    if (f2 && (strcmp(f2, "all") || !strcmp(f1, "all"))) {
        strarray_free(fields);
        free(lcasename);
        free(name);
        return NULL;
    }
    if (f1) {
        if (!strcmp(f1, "asRaw"))
            form = HEADER_FORM_RAW;
        else if (!strcmp(f1, "asText"))
            form = HEADER_FORM_TEXT;
        else if (!strcmp(f1, "asAddresses"))
            form = HEADER_FORM_ADDRESSES;
        else if (!strcmp(f1, "asMessageIds"))
            form = HEADER_FORM_MESSAGEIDS;
        else if (!strcmp(f1, "asDate"))
            form = HEADER_FORM_DATE;
        else if (!strcmp(f1, "asURLs"))
            form = HEADER_FORM_URLS;
        else if (strcmp(f1, "all"))
            is_valid = 0;
    }

    /* Validate requested header form */
    if (is_valid && form != HEADER_FORM_RAW) {
        enum _header_form allowed_form = (enum _header_form) \
                                         hash_lookup(lcasename, &allowed_header_forms);
        if (allowed_form != HEADER_FORM_UNKNOWN && form != allowed_form) {
            is_valid = 0;
        }
    }

    struct header_prop *hprop = NULL;
    if (is_valid) {
        hprop = xzmalloc(sizeof(struct header_prop));
        hprop->lcasename = lcasename;
        hprop->name = name;
        hprop->prop = s;
        hprop->form = form;
        hprop->all = f2 != NULL || (f1 && !strcmp(f1, "all"));
    }
    else {
        free(lcasename);
        free(name);
    }
    strarray_free(fields);
    return hprop;
}

/* Generate a preview of text of at most len bytes, excluding the zero
 * byte.
 *
 * Consecutive whitespaces, including newlines, are collapsed to a single
 * blank. If text is longer than len and len is greater than 4, then return
 * a string  ending in '...' and holding as many complete UTF-8 characters,
 * that the total byte count of non-zero characters is at most len.
 *
 * The input string must be properly encoded UTF-8 */
static char *_email_extract_preview(const char *text, size_t len)
{
    unsigned char *dst, *d, *t;
    size_t n;

    if (!text) {
        return NULL;
    }

    /* Replace all whitespace with single blanks. */
    dst = (unsigned char *) xzmalloc(len+1);
    for (t = (unsigned char *) text, d = dst; *t && d < (dst+len); ++t, ++d) {
        *d = isspace(*t) ? ' ' : *t;
        if (isspace(*t)) {
            while(isspace(*++t))
                ;
            --t;
        }
    }
    n = d - dst;

    /* Anything left to do? */
    if (n < len || len <= 4) {
        return (char*) dst;
    }

    /* Append trailing ellipsis. */
    dst[--n] = '.';
    dst[--n] = '.';
    dst[--n] = '.';
    while (n && (dst[n] & 0xc0) == 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    if (dst[n] >= 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    return (char *) dst;
}

// struct _email_mailboxes_rock {
//     jmap_req_t *req;
//     json_t *mboxs;
// };

// static int _email_mailboxes_cb(const conv_guidrec_t *rec, void *rock)
// {
//     struct _email_mailboxes_rock *data = (struct _email_mailboxes_rock*) rock;
//     json_t *mboxs = data->mboxs;
//     jmap_req_t *req = data->req;
//     struct mailbox *mbox = NULL;
//     msgrecord_t *mr = NULL;
//     uint32_t system_flags, internal_flags;
//     int r;

//     if (rec->part) return 0;

//     static int needrights = ACL_READ|ACL_LOOKUP;
//     if (!jmap_hasrights_byname(req, rec->mboxname, needrights))
//         return 0;

//     r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
//     if (r) return r;

//     // we only want regular mailboxes!
//     if (mbox->mbtype & MBTYPES_NONIMAP) goto done;

//     r = msgrecord_find(mbox, rec->uid, &mr);
//     if (r) goto done;

//     r = msgrecord_get_systemflags(mr, &system_flags);
//     if (r) goto done;

//     r = msgrecord_get_internalflags(mr, &internal_flags);
//     if (r) goto done;

//     if (!r) {
//         char datestr[RFC3339_DATETIME_MAX];
//         time_t t;
//         int exists = 1;

//         if (system_flags & FLAG_DELETED || internal_flags & FLAG_INTERNAL_EXPUNGED) {
//             exists = 0;
//             r = msgrecord_get_lastupdated(mr, &t);
//         }
//         else {
//             r = msgrecord_get_savedate(mr, &t);
//         }

//         if (r) goto done;
//         time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);

//         json_t *mboxdata = json_object_get(mboxs, mbox->uniqueid);
//         if (!mboxdata) {
//             mboxdata = json_object();
//             json_object_set_new(mboxs, mbox->uniqueid, mboxdata);
//         }

//         if (exists) {
//             json_t *prev = json_object_get(mboxdata, "added");
//             if (prev) {
//                 const char *val = json_string_value(prev);
//                 // we want the FIRST date it was added to the mailbox, so skip if this is newer
//                 if (strcmp(datestr, val) >= 0) goto done;
//             }

//             json_object_set_new(mboxdata, "added", json_string(datestr));
//         }
//         else {
//             json_t *prev = json_object_get(mboxdata, "removed");
//             if (prev) {
//                 const char *val = json_string_value(prev);
//                 // we want the LAST date it was removed from the mailbox, so skip if this is older
//                 if (strcmp(datestr, val) <= 0) goto done;
//             }

//             json_object_set_new(mboxdata, "removed", json_string(datestr));
//         }
//     }


// done:
//     if (mr) msgrecord_unref(&mr);
//     jmap_closembox(req, &mbox);
//     return r;
// }

static char *_emailbodies_to_plain(struct emailbodies *bodies, const struct buf *msg_buf)
{
    if (bodies->textlist.count == 1) {
        int is_encoding_problem = 0;
        struct body *textbody = ptrarray_nth(&bodies->textlist, 0);
        char *text = _decode_to_utf8(textbody->charset_id,
                                     msg_buf->s + textbody->content_offset,
                                     textbody->content_size,
                                     textbody->encoding,
                                     &is_encoding_problem);
        return text;
    }

    /* Concatenate all plain text bodies and replace any
     * inlined images with placeholders. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->textlist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->textlist, i);

        if (i) buf_appendcstr(&buf, "\n");

        if (!strcmp(part->type, "TEXT")) {
            int is_encoding_problem = 0;
            char *t = _decode_to_utf8(part->charset_id,
                                      msg_buf->s + part->content_offset,
                                      part->content_size,
                                      part->encoding,
                                      &is_encoding_problem);
            if (t) buf_appendcstr(&buf, t);
            free(t);
        }
        else if (!strcmp(part->type, "IMAGE")) {
            struct param *param;
            const char *fname = NULL;
            for (param = part->disposition_params; param; param = param->next) {
                if (!strncasecmp(param->attribute, "filename", 8)) {
                    fname =param->value;
                    break;
                }
            }
            buf_appendcstr(&buf, "[Inline image");
            if (fname) {
                buf_appendcstr(&buf, ":");
                buf_appendcstr(&buf, fname);
            }
            buf_appendcstr(&buf, "]");
        }
    }
    return buf_release(&buf);
}

/* Replace any <HTML> and </HTML> tags in t with <DIV> and </DIV>,
 * writing results into buf */
static void _html_concat_div(struct buf *buf, const char *t)
{
    const char *top = t + strlen(t);
    const char *p = t, *q = p;

    while (*q) {
        const char *tag = NULL;
        if (q < top - 5 && !strncasecmp(q, "<html", 5) &&
                (*(q+5) == '>' || isspace(*(q+5)))) {
            /* Found a <HTML> tag */
            tag = "<div>";
        }
        else if (q < top - 6 && !strncasecmp(q, "</html", 6) &&
                (*(q+6) == '>' || isspace(*(q+6)))) {
            /* Found a </HTML> tag */
            tag = "</div>";
        }

        /* No special tag? */
        if (!tag) {
            q++;
            continue;
        }

        /* Append whatever we saw since the last HTML tag. */
        buf_appendmap(buf, p, q - p);

        /* Look for the end of the tag and replace it, even if
         * it prematurely ends at the end of the buffer . */
        while (*q && *q != '>') { q++; }
        buf_appendcstr(buf, tag);
        if (*q) q++;

        /* Prepare for next loop */
        p = q;
    }
    buf_appendmap(buf, p, q - p);
}


static char *_emailbodies_to_html(struct emailbodies *bodies, const struct buf *msg_buf)
{
    if (bodies->htmllist.count == 1) {
        const struct body *part = ptrarray_nth(&bodies->htmllist, 0);
        int is_encoding_problem = 0;
        char *html = _decode_to_utf8(part->charset_id,
                                     msg_buf->s + part->content_offset,
                                     part->content_size,
                                     part->encoding,
                                     &is_encoding_problem);
        return html;
    }

    /* Concatenate all TEXT bodies, enclosing PLAIN text
     * in <div> and replacing <html> tags in HTML bodies
     * with <div>. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->htmllist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->htmllist, i);

        /* XXX htmllist might include inlined images but we
         * currently ignore them. After all, there should
         * already be an <img> tag for their Content-Id
         * header value. If this turns out to be not enough,
         * we can insert the <img> tags here. */
        if (strcasecmp(part->type, "TEXT")) {
            continue;
        }

        if (!i)
            buf_appendcstr(&buf, "<html>"); // XXX use HTML5?

        int is_encoding_problem = 0;
        char *t = _decode_to_utf8(part->charset_id,
                                  msg_buf->s + part->content_offset,
                                  part->content_size,
                                  part->encoding,
                                  &is_encoding_problem);
        if (t && !strcmp(part->subtype, "HTML")) {
            _html_concat_div(&buf, t);
        }
        else if (t) {
            buf_appendcstr(&buf, "<div>");
            buf_appendcstr(&buf, t);
            buf_appendcstr(&buf, "</div>");
        }
        free(t);

        if (i == bodies->htmllist.count - 1)
            buf_appendcstr(&buf, "</html>");
    }
    return buf_release(&buf);
}

static void _html_to_plain_cb(const struct buf *buf, void *rock)
{
    struct buf *dst = (struct buf*) rock;
    const char *p;
    int seenspace = 0;

    /* Just merge multiple space into one. That's similar to
     * charset_extract's MERGE_SPACE but since we don't want
     * it to canonify the text into search form */
    for (p = buf_base(buf); p < buf_base(buf) + buf_len(buf) && *p; p++) {
        if (*p == ' ') {
            if (seenspace) continue;
            seenspace = 1;
        } else {
            seenspace = 0;
        }
        buf_appendmap(dst, p, 1);
    }
}

static char *_html_to_plain(const char *html) {
    struct buf src = BUF_INITIALIZER;
    struct buf dst = BUF_INITIALIZER;
    charset_t utf8 = charset_lookupname("utf8");
    char *text;
    char *tmp, *q;
    const char *p;

    /* Replace <br> and <p> with newlines */
    q = tmp = xstrdup(html);
    p = html;
    while (*p) {
        if (!strncmp(p, "<br>", 4) || !strncmp(p, "</p>", 4)) {
            *q++ = '\n';
            p += 4;
        }
        else if (!strncmp(p, "p>", 3)) {
            p += 3;
        } else {
            *q++ = *p++;
        }
    }
    *q = 0;

    /* Strip html tags */
    buf_init_ro(&src, tmp, q - tmp);
    buf_setcstr(&dst, "");
    charset_extract(&_html_to_plain_cb, &dst,
            &src, utf8, ENCODING_NONE, "HTML", CHARSET_KEEPCASE);
    buf_cstring(&dst);

    /* Trim text */
    buf_trim(&dst);
    text = buf_releasenull(&dst);
    if (!strlen(text)) {
        free(text);
        text = NULL;
    }

    buf_free(&src);
    free(tmp);
    charset_free(&utf8);

    return text;
}

// static const char *_guid_from_id(const char *msgid)
// {
//     return msgid + 1;
// }

// static conversation_id_t _cid_from_id(const char *thrid)
// {
//     conversation_id_t cid = 0;
//     if (thrid[0] == 'T')
//         conversation_id_decode(&cid, thrid+1);
//     return cid;
// }

// /*
//  * Lookup all mailboxes where msgid is contained in.
//  *
//  * The return value is a JSON object keyed by the mailbox unique id,
//  * and its mailbox name as value.
//  */
// static json_t *_email_mailboxes(jmap_req_t *req, const char *msgid)
// {
//     struct _email_mailboxes_rock data = { req, json_pack("{}") };
//     conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_mailboxes_cb, &data);
//     return data.mboxs;
// }



// static void _email_read_annot(const jmap_req_t *req, msgrecord_t *mr,
//                               const char *annot, struct buf *buf)
// {
//     if (!strncmp(annot, "/shared/", 8)) {
//         msgrecord_annot_lookup(mr, annot+7, /*userid*/"", buf);
//     }
//     else if (!strncmp(annot, "/private/", 9)) {
//         msgrecord_annot_lookup(mr, annot+7, req->userid, buf);
//     }
//     else {
//         msgrecord_annot_lookup(mr, annot, "", buf);
//     }
// }

// static json_t *_email_read_jannot(const jmap_req_t *req, msgrecord_t *mr,
//                                   const char *annot, int structured)
// {
//     struct buf buf = BUF_INITIALIZER;
//     json_t *annotvalue = NULL;

//     _email_read_annot(req, mr, annot, &buf);

//     if (buf_len(&buf)) {
//         if (structured) {
//             json_error_t jerr;
//             annotvalue = json_loads(buf_cstring(&buf), JSON_DECODE_ANY, &jerr);
//             /* XXX - log error? */
//         }
//         else {
//             annotvalue = json_string(buf_cstring(&buf));
//         }

//         if (!annotvalue) {
//             syslog(LOG_ERR, "jmap: annotation %s has bogus value", annot);
//         }
//     }
//     buf_free(&buf);
//     return annotvalue;
// }


// struct _email_find_rock {
//     jmap_req_t *req;
//     char *mboxname;
//     uint32_t uid;
// };

// static int _email_find_cb(const conv_guidrec_t *rec, void *rock)
// {
//     struct _email_find_rock *d = (struct _email_find_rock*) rock;
//     jmap_req_t *req = d->req;

//     if (rec->part) return 0;

//     /* Make sure we are allowed to read this mailbox */
//     if (!jmap_hasrights_byname(req, rec->mboxname, ACL_READ))
//         return 0;

//     int r = 0;
//     struct mailbox *mbox = NULL;
//     msgrecord_t *mr = NULL;
//     uint32_t system_flags;
//     uint32_t internal_flags;

//     r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
//     if (r) {
//         // we want to keep looking and see if we can find a mailbox we can open
//         syslog(LOG_ERR, "IOERROR: email_find_cb failed to open %s: %s",
//                rec->mboxname, error_message(r));
//         goto done;
//     }

//     r = msgrecord_find(mbox, rec->uid, &mr);
//     if (!r) r = msgrecord_get_systemflags(mr, &system_flags);
//     if (!r) r = msgrecord_get_internalflags(mr, &internal_flags);
//     if (r) {
//         // we want to keep looking and see if we can find a message we can read
//         syslog(LOG_ERR, "IOERROR: email_find_cb failed to find message %u in mailbox %s: %s",
//                rec->uid, rec->mboxname, error_message(r));
//         goto done;
//     }

//     // if it's deleted, skip
//     if ((system_flags & FLAG_DELETED) || (internal_flags & FLAG_INTERNAL_EXPUNGED))
//         goto done;

//     d->mboxname = xstrdup(rec->mboxname);
//     d->uid = rec->uid;

// done:
//     jmap_closembox(req, &mbox);
//     msgrecord_unref(&mr);
//     return d->mboxname ? IMAP_OK_COMPLETED : 0;
// }

// static int _email_find_in_account(jmap_req_t *req,
//                                   const char *account_id,
//                                   const char *email_id,
//                                   char **mboxnameptr,
//                                   uint32_t *uidptr)
// {
//     struct _email_find_rock rock = { req, NULL, 0 };
//     int r;

//     /* must be prefixed with 'M' */
//     if (email_id[0] != 'M')
//         return IMAP_NOTFOUND;
//     /* this is on a 24 character prefix only */
//     if (strlen(email_id) != 25)
//         return IMAP_NOTFOUND;
//     /* Open conversation state, if not already open */
//     struct conversations_state *mycstate = NULL;
//     if (strcmp(req->accountid, account_id)) {
//         r = conversations_open_user(account_id, 1/*shared*/, &mycstate);
//         if (r) return r;
//     }
//     else {
//         mycstate = req->cstate;
//     }
//     r = conversations_guid_foreach(mycstate, _guid_from_id(email_id),
//                                    _email_find_cb, &rock);
//     if (mycstate != req->cstate) {
//         conversations_commit(&mycstate);
//     }
//     /* Set return values */
//     if (r == IMAP_OK_COMPLETED)
//         r = 0;
//     else if (!rock.mboxname)
//         r = IMAP_NOTFOUND;
//     *mboxnameptr = rock.mboxname;
//     *uidptr = rock.uid;
//     return r;
// }

// HIDDEN int jmap_email_find(jmap_req_t *req,
//                            const char *email_id,
//                            char **mboxnameptr,
//                            uint32_t *uidptr)
// {
//     return _email_find_in_account(req, req->accountid, email_id, mboxnameptr, uidptr);
// }

// struct email_getcid_rock {
//     jmap_req_t *req;
//     int checkacl;
//     conversation_id_t cid;
// };

// static int _email_get_cid_cb(const conv_guidrec_t *rec, void *rock)
// {
//     struct email_getcid_rock *d = (struct email_getcid_rock *)rock;
//     if (rec->part) return 0;
//     if (!rec->cid) return 0;
//     /* Make sure we are allowed to read this mailbox */
//     if (d->checkacl && !jmap_hasrights_byname(d->req, rec->mboxname, ACL_READ))
//             return 0;
//     d->cid = rec->cid;
//     return IMAP_OK_COMPLETED;
// }

// static int _email_get_cid(jmap_req_t *req, const char *msgid,
//                            conversation_id_t *cidp)
// {
//     int r;

//     /* must be prefixed with 'M' */
//     if (msgid[0] != 'M')
//         return IMAP_NOTFOUND;
//     /* this is on a 24 character prefix only */
//     if (strlen(msgid) != 25)
//         return IMAP_NOTFOUND;

//     int checkacl = strcmp(req->userid, req->accountid);
//     struct email_getcid_rock rock = { req, checkacl, 0 };
//     r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_get_cid_cb, &rock);
//     if (r == IMAP_OK_COMPLETED) {
//         *cidp = rock.cid;
//         r = 0;
//     }
//     return r;
// }

// struct email_expunge_check {
//     jmap_req_t *req;
//     modseq_t since_modseq;
//     int status;
// };

// static int _email_is_expunged_cb(const conv_guidrec_t *rec, void *rock)
// {
//     struct email_expunge_check *check = rock;
//     msgrecord_t *mr = NULL;
//     struct mailbox *mbox = NULL;
//     uint32_t flags;
//     int r = 0;

//     if (rec->part) return 0;

//     r = jmap_openmbox(check->req, rec->mboxname, &mbox, 0);
//     if (r) return r;

//     r = msgrecord_find(mbox, rec->uid, &mr);
//     if (!r) {
//         uint32_t internal_flags;
//         modseq_t createdmodseq;
//         r = msgrecord_get_systemflags(mr, &flags);
//         if (!r) msgrecord_get_internalflags(mr, &internal_flags);
//         if (!r) msgrecord_get_createdmodseq(mr, &createdmodseq);
//         if (!r) {
//             /* OK, this is a legit record, let's check it out */
//             if (createdmodseq <= check->since_modseq)
//                 check->status |= 1;  /* contains old messages */
//             if (!((flags & FLAG_DELETED) || (internal_flags & FLAG_INTERNAL_EXPUNGED)))
//                 check->status |= 2;  /* contains alive messages */
//         }
//         msgrecord_unref(&mr);
//     }

//     jmap_closembox(check->req, &mbox);
//     return 0;
// }

// static void _email_search_perf_attr(const search_attr_t *attr, strarray_t *perf_filters)
// {
//     const char *cost = NULL;

//     switch (search_attr_cost(attr)) {
//         case SEARCH_COST_INDEX:
//             cost = "index";
//             break;
//         case SEARCH_COST_CONV:
//             cost = "conversations";
//             break;
//         case SEARCH_COST_ANNOT:
//             cost = "annotations";
//             break;
//         case SEARCH_COST_CACHE:
//             cost = "cache";
//             break;
//         case SEARCH_COST_BODY:
//             cost = search_attr_is_fuzzable(attr) ? "xapian" : "body";
//             break;
//         default:
//             ; // ignore
//     }

//     if (cost) strarray_add(perf_filters, cost);
// }

// static void _email_search_string(search_expr_t *parent,
//                                  const char *s,
//                                  const char *name,
//                                  strarray_t *perf_filters)
// {
//     charset_t utf8 = charset_lookupname("utf-8");
//     search_expr_t *e;
//     const search_attr_t *attr = search_attr_find(name);
//     enum search_op op;

//     assert(attr);

//     op = search_attr_is_fuzzable(attr) ? SEOP_FUZZYMATCH : SEOP_MATCH;

//     e = search_expr_new(parent, op);
//     e->attr = attr;
//     e->value.s = charset_convert(s, utf8, charset_flags);
//     if (!e->value.s) {
//         e->op = SEOP_FALSE;
//         e->attr = NULL;
//     }

//     _email_search_perf_attr(attr, perf_filters);
//     charset_free(&utf8);
// }

// static void _email_search_type(search_expr_t *parent, const char *s, strarray_t *perf_filters)
// {
//     strarray_t types = STRARRAY_INITIALIZER;

//     /* Handle type wildcards */
//     // XXX: due to Xapian's 64 character indexing limitation, we're not prefixing application_
//     // to the Microsoft types
//     if (!strcasecmp(s, "image")) {
//         strarray_append(&types, "image_gif");
//         strarray_append(&types, "image_jpeg");
//         strarray_append(&types, "image_pjpeg");
//         strarray_append(&types, "image_jpg");
//         strarray_append(&types, "image_png");
//         strarray_append(&types, "image_bmp");
//         strarray_append(&types, "image_tiff");
//     }
//     else if (!strcasecmp(s, "document")) {
//         strarray_append(&types, "application_msword");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.wordprocessingml.document");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.wordprocessingml.template");
//         strarray_append(&types, "application_vnd.sun.xml.writer");
//         strarray_append(&types, "application_vnd.sun.xml.writer.template");
//         strarray_append(&types, "application_vnd.oasis.opendocument.text");
//         strarray_append(&types, "application_vnd.oasis.opendocument.text-template");
//         strarray_append(&types, "application_x-iwork-pages-sffpages");
//         strarray_append(&types, "application_vnd.apple.pages");
//     }
//     else if (!strcasecmp(s, "spreadsheet")) {
//         strarray_append(&types, "application_vnd.ms-excel");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.spreadsheetml.sheet");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.spreadsheetml.template");
//         strarray_append(&types, "application_vnd.sun.xml.calc");
//         strarray_append(&types, "application_vnd.sun.xml.calc.template");
//         strarray_append(&types, "application_vnd.oasis.opendocument.spreadsheet");
//         strarray_append(&types, "application_vnd.oasis.opendocument.spreadsheet-template");
//         strarray_append(&types, "application_x-iwork-numbers-sffnumbers");
//         strarray_append(&types, "application_vnd.apple.numbers");
//     }
//     else if (!strcasecmp(s, "presentation")) {
//         strarray_append(&types, "application_vnd.ms-powerpoint");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.presentationml.presentation");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.presentationml.template");
//         strarray_append(&types, "vnd.openxmlformats-officedocument.presentationml.slideshow");
//         strarray_append(&types, "application_vnd.sun.xml.impress");
//         strarray_append(&types, "application_vnd.sun.xml.impress.template");
//         strarray_append(&types, "application_vnd.oasis.opendocument.presentation");
//         strarray_append(&types, "application_vnd.oasis.opendocument.presentation-template");
//         strarray_append(&types, "application_x-iwork-keynote-sffkey");
//         strarray_append(&types, "application_vnd.apple.keynote");
//     }
//     else if (!strcasecmp(s, "email")) {
//         strarray_append(&types, "message_rfc822");
//     }
//     else if (!strcasecmp(s, "pdf")) {
//         strarray_append(&types, "application_pdf");
//     }
//     else {
//         /* FUZZY contenttype is indexed as `type_subtype` */
//         char *tmp = xstrdup(s);
//         char *p = strchr(tmp, '/');
//         if (p) *p = '_';
//         strarray_append(&types, tmp);
//         free(tmp);
//     }

//     /* Build expression */
//     search_expr_t *p = (types.count > 1) ? search_expr_new(parent, SEOP_OR) : parent;
//     const search_attr_t *attr = search_attr_find("contenttype");
//     do {
//         search_expr_t *e = search_expr_new(p, SEOP_FUZZYMATCH);
//         e->attr = attr;
//         struct buf buf = BUF_INITIALIZER;
//         char *orig = strarray_pop(&types);
//         const unsigned char *s = (const unsigned char *)orig;
//         for ( ; *s ; ++s) {
//             if (Uisalnum(*s) || *s == '_')
//                 buf_putc(&buf, *s);
//         }
//         e->value.s = buf_release(&buf);
//         free(orig);
//         buf_free(&buf);
//     } while (types.count);
//     _email_search_perf_attr(attr, perf_filters);

//     strarray_fini(&types);
// }

// static void _email_search_keyword(search_expr_t *parent, const char *keyword, strarray_t *perf_filters)
// {
//     search_expr_t *e;
//     if (!strcasecmp(keyword, "$Seen")) {
//         e = search_expr_new(parent, SEOP_MATCH);
//         e->attr = search_attr_find("indexflags");
//         e->value.u = MESSAGE_SEEN;
//     }
//     else if (!strcasecmp(keyword, "$Draft")) {
//         e = search_expr_new(parent, SEOP_MATCH);
//         e->attr = search_attr_find("systemflags");
//         e->value.u = FLAG_DRAFT;
//     }
//     else if (!strcasecmp(keyword, "$Flagged")) {
//         e = search_expr_new(parent, SEOP_MATCH);
//         e->attr = search_attr_find("systemflags");
//         e->value.u = FLAG_FLAGGED;
//     }
//     else if (!strcasecmp(keyword, "$Answered")) {
//         e = search_expr_new(parent, SEOP_MATCH);
//         e->attr = search_attr_find("systemflags");
//         e->value.u = FLAG_ANSWERED;
//     }
//     else {
//         e = search_expr_new(parent, SEOP_MATCH);
//         e->attr = search_attr_find("keyword");
//         e->value.s = xstrdup(keyword);
//     }
//     _email_search_perf_attr(e->attr, perf_filters);
// }

// static void _email_search_threadkeyword(search_expr_t *parent, const char *keyword,
//                                         int matchall, strarray_t *perf_filters)
// {
//     const char *flag = jmap_keyword_to_imap(keyword);
//     if (!flag) return;

//     search_expr_t *e = search_expr_new(parent, SEOP_MATCH);
//     e->attr = search_attr_find(matchall ? "allconvflags" : "convflags");
//     e->value.s = xstrdup(flag);
//     _email_search_perf_attr(e->attr, perf_filters);
// }

// static void _email_search_contactgroup(search_expr_t *parent,
//                                        const char *groupid,
//                                        const char *attrname,
//                                        hash_table *contactgroups,
//                                        strarray_t *perf_filters)
// {
//     if (!contactgroups || !contactgroups->size) return;

//     strarray_t *members = hash_lookup(groupid, contactgroups);
//     if (members && strarray_size(members)) {
//         search_expr_t *e = search_expr_new(parent, SEOP_OR);
//         int j;
//         for (j = 0; j < strarray_size(members); j++) {
//             _email_search_string(e, strarray_nth(members, j),
//                     attrname, perf_filters);
//         }
//     }
// }

// /* ====================================================================== */

// static void _emailsearch_folders_internalise(struct index_state *state,
//                                              const union search_value *v,
//                                              void **internalisedp)
// {
//     if (state && v) {
//         *internalisedp = mailbox_get_cstate(state->mailbox);
//     }
// }

// struct jmap_search_folder_match_rock {
//     const strarray_t *folders;
//     intptr_t is_otherthan;
// };

// static int _emailsearch_folders_match_cb(const conv_guidrec_t *rec, void *rock)
// {
//     if ((rec->system_flags & FLAG_DELETED) ||
//         (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)) return 0;

//     // TODO we could match for mboxid, once the mailbox-id patch lands
//     struct jmap_search_folder_match_rock *myrock = rock;
//     int pos = strarray_find(myrock->folders, rec->mboxname, 0);
//     return ((pos >= 0) == (myrock->is_otherthan == 0)) ? IMAP_OK_COMPLETED : 0;
// }

// static int _emailsearch_folders_match(message_t *m, const union search_value *v,
//                                       void *internalised,
//                                       void *data1)
// {
//     struct conversations_state *cstate = internalised;
//     if (!cstate) return 0;
//     const struct message_guid *guid = NULL;
//     int r = message_get_guid(m, &guid);
//     if (r) return 0;
//     struct jmap_search_folder_match_rock rock = { v->rock, (intptr_t) data1 };
//     r = conversations_guid_foreach(cstate, message_guid_encode(guid),
//                                    _emailsearch_folders_match_cb, &rock);
//     return r == IMAP_OK_COMPLETED;
// }

// static void _emailsearch_folders_serialise(struct buf *buf,
//                                            const union search_value *v)
// {
//     char *tmp = strarray_join((strarray_t*)v->rock, " ");
//     buf_putc(buf, '(');
//     buf_appendcstr(buf, tmp);
//     buf_putc(buf, ')');
//     free(tmp);
// }

// static int _emailsearch_folders_unserialise(struct protstream* prot,
//                                             union search_value *v)
// {
//     struct dlist *dl = NULL;

//     int c = dlist_parse_asatomlist(&dl, 0, prot);
//     if (c == EOF) return EOF;

//     strarray_t *folders = strarray_new();
//     struct buf tmp = BUF_INITIALIZER;
//     struct dlist_print_iter *iter = dlist_print_iter_new(dl, /*printkeys*/ 0);
//     while (iter && dlist_print_iter_step(iter, &tmp)) {
//         if (buf_len(&tmp)) strarray_append(folders, buf_cstring(&tmp));
//         buf_reset(&tmp);
//     }
//     dlist_print_iter_free(&iter);
//     buf_free(&tmp);
//     v->rock = folders;
//     return c;
// }

// static void _emailsearch_folders_duplicate(union search_value *new,
//                                            const union search_value *old)
// {
//     new->rock = strarray_dup((strarray_t*)old->rock);
// }

// static void _emailsearch_folders_free(union search_value *v)
// {
//     strarray_free(v->rock);
// }

// static const search_attr_t _emailsearch_folders_attr = {
//     "jmap_folders",
//     SEA_MUTABLE,
//     SEARCH_PART_NONE,
//     SEARCH_COST_CONV,
//     _emailsearch_folders_internalise,
//     /*cmp*/NULL,
//     _emailsearch_folders_match,
//     _emailsearch_folders_serialise,
//     _emailsearch_folders_unserialise,
//     /*get_countability*/NULL,
//     _emailsearch_folders_duplicate,
//     _emailsearch_folders_free,
//     (void*)0 /*is_otherthan*/
// };

// static const search_attr_t _emailsearch_folders_otherthan_attr = {
//     "jmap_folders_otherthan",
//     SEA_MUTABLE,
//     SEARCH_PART_NONE,
//     SEARCH_COST_CONV,
//     _emailsearch_folders_internalise,
//     /*cmp*/NULL,
//     _emailsearch_folders_match,
//     _emailsearch_folders_serialise,
//     _emailsearch_folders_unserialise,
//     /*get_countability*/NULL,
//     _emailsearch_folders_duplicate,
//     _emailsearch_folders_free,
//     (void*)1 /*is_otherthan*/
// };


// /* ====================================================================== */

// static search_expr_t *_email_buildsearchexpr(jmap_req_t *req, json_t *filter,
//                                              search_expr_t *parent,
//                                              hash_table *contactgroups,
//                                              strarray_t *perf_filters)
// {
//     search_expr_t *this, *e;
//     json_t *val;
//     const char *s;
//     size_t i;
//     time_t t;

//     if (!JNOTNULL(filter)) {
//         return search_expr_new(parent, SEOP_TRUE);
//     }

//     if ((s = json_string_value(json_object_get(filter, "operator")))) {
//         enum search_op op = SEOP_UNKNOWN;

//         if (!strcmp("AND", s)) {
//             op = SEOP_AND;
//         } else if (!strcmp("OR", s)) {
//             op = SEOP_OR;
//         } else if (!strcmp("NOT", s)) {
//             op = SEOP_NOT;
//         }

//         this = search_expr_new(parent, op);
//         e = op == SEOP_NOT ? search_expr_new(this, SEOP_OR) : this;

//         json_array_foreach(json_object_get(filter, "conditions"), i, val) {
//             _email_buildsearchexpr(req, val, e, contactgroups, perf_filters);
//         }
//     } else {
//         this = search_expr_new(parent, SEOP_AND);

//         /* zero properties evaluate to true */
//         search_expr_new(this, SEOP_TRUE);

//         if ((s = json_string_value(json_object_get(filter, "after")))) {
//             time_from_iso8601(s, &t);
//             e = search_expr_new(this, SEOP_GE);
//             e->attr = search_attr_find("internaldate");
//             e->value.u = t;
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "before")))) {
//             time_from_iso8601(s, &t);
//             e = search_expr_new(this, SEOP_LE);
//             e->attr = search_attr_find("internaldate");
//             e->value.u = t;
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "body")))) {
//             _email_search_string(this, s, "body", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "cc")))) {
//             _email_search_string(this, s, "cc", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "bcc")))) {
//             _email_search_string(this, s, "bcc", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "from")))) {
//             _email_search_string(this, s, "from", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "fromContactGroupId")))) {
//             _email_search_contactgroup(this, s, "from", contactgroups, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "toContactGroupId")))) {
//             _email_search_contactgroup(this, s, "to", contactgroups, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "ccContactGroupId")))) {
//             _email_search_contactgroup(this, s, "cc", contactgroups, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "bccContactGroupId")))) {
//             _email_search_contactgroup(this, s, "bcc", contactgroups, perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "hasAttachment")))) {
//             e = val == json_false() ? search_expr_new(this, SEOP_NOT) : this;
//             e = search_expr_new(e, SEOP_MATCH);
//             e->attr = search_attr_find("keyword");
//             e->value.s = xstrdup(JMAP_HAS_ATTACHMENT_FLAG);
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "attachmentName")))) {
//             _email_search_string(this, s, "attachmentname", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "attachmentType")))) {
//             _email_search_type(this, s, perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "header")))) {
//             const char *k, *v;
//             charset_t utf8 = charset_lookupname("utf-8");
//             search_expr_t *e;

//             if (json_array_size(val) == 2) {
//                 k = json_string_value(json_array_get(val, 0));
//                 v = json_string_value(json_array_get(val, 1));
//             } else {
//                 k = json_string_value(json_array_get(val, 0));
//                 v = ""; /* Empty string matches any value */
//             }

//             e = search_expr_new(this, SEOP_MATCH);
//             e->attr = search_attr_find_field(k);
//             e->value.s = charset_convert(v, utf8, charset_flags);
//             if (!e->value.s) {
//                 e->op = SEOP_FALSE;
//                 e->attr = NULL;
//             }
//             _email_search_perf_attr(e->attr, perf_filters);
//             charset_free(&utf8);
//         }
//         if ((val = json_object_get(filter, "inMailbox"))) {
//             strarray_t *folders = strarray_new();
//             const char *mboxid = json_string_value(val);
//             const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
//             if (mbentry && jmap_hasrights(req, mbentry, ACL_LOOKUP)) {
//                 strarray_append(folders, mbentry->name);
//             }
//             if (strarray_size(folders)) {
//                 search_expr_t *e = search_expr_new(this, SEOP_MATCH);
//                 e->attr = &_emailsearch_folders_attr;
//                 e->value.rock = folders;
//                 strarray_add(perf_filters, "mailbox");
//             }
//         }

//         if ((val = json_object_get(filter, "inMailboxOtherThan"))) {
//             strarray_t *folders = strarray_new();
//             json_t *jmboxid;
//             json_array_foreach(val, i, jmboxid) {
//                 const char *mboxid = json_string_value(jmboxid);
//                 const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
//                 if (mbentry && jmap_hasrights(req, mbentry, ACL_LOOKUP)) {
//                     strarray_append(folders, mbentry->name);
//                 }
//             }
//             if (strarray_size(folders)) {
//                 search_expr_t *e = search_expr_new(this, SEOP_MATCH);
//                 e->attr = &_emailsearch_folders_otherthan_attr;
//                 e->value.rock = folders;
//                 strarray_add(perf_filters, "mailbox");
//             }
//         }

//         if (JNOTNULL((val = json_object_get(filter, "allInThreadHaveKeyword")))) {
//             /* This shouldn't happen, validate_sort should have reported
//              * allInThreadHaveKeyword as unsupported. Let's ignore this
//              * filter and return false positives. */
//             _email_search_threadkeyword(this, json_string_value(val), 1, perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "someInThreadHaveKeyword")))) {
//             _email_search_threadkeyword(this, json_string_value(val), 0, perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "noneInThreadHaveKeyword")))) {
//             e = search_expr_new(this, SEOP_NOT);
//             _email_search_threadkeyword(e, json_string_value(val), 0, perf_filters);
//         }

//         if (JNOTNULL((val = json_object_get(filter, "hasKeyword")))) {
//             _email_search_keyword(this, json_string_value(val), perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "notKeyword")))) {
//             e = search_expr_new(this, SEOP_NOT);
//             _email_search_keyword(e, json_string_value(val), perf_filters);
//         }

//         if (JNOTNULL((val = json_object_get(filter, "maxSize")))) {
//             e = search_expr_new(this, SEOP_LE);
//             e->attr = search_attr_find("size");
//             e->value.u = json_integer_value(val);
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if (JNOTNULL((val = json_object_get(filter, "minSize")))) {
//             e = search_expr_new(this, SEOP_GE);
//             e->attr = search_attr_find("size");
//             e->value.u = json_integer_value(val);
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "sinceEmailState")))) {
//             /* non-standard */
//             e = search_expr_new(this, SEOP_GT);
//             e->attr = search_attr_find("modseq");
//             e->value.u = atomodseq_t(s);
//             _email_search_perf_attr(e->attr, perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "subject")))) {
//             _email_search_string(this, s, "subject", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "text")))) {
//             _email_search_string(this, s, "text", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "attachmentBody")))) {
//             _email_search_string(this, s, "attachmentbody", perf_filters);
//         }
//         if ((s = json_string_value(json_object_get(filter, "to")))) {
//             _email_search_string(this, s, "to", perf_filters);
//         }
//     }

//     return this;
// }

// static search_expr_t *_email_buildsearch(jmap_req_t *req, json_t *filter,
//                                          hash_table *contactgroups,
//                                          strarray_t *perf_filters)
// {
//     search_expr_t *root = _email_buildsearchexpr(req, filter, /*parent*/NULL,
//                                                  contactgroups, perf_filters);

//     /* The search API internally optimises for IMAP folder queries
//      * and we'd like to benefit from this also for JMAP. To do so,
//      * we try to convert as many inMailboxId expressions to IMAP
//      * mailbox matches as possible. This includes the first
//      * inMailboxId that is part of a positive AND and any inMailboxId
//      * that is part of a positive OR expression. */
//     ptrarray_t todo = PTRARRAY_INITIALIZER;
//     int found_and_match = 0;
//     struct work {
//         search_expr_t *e;
//         int in_or;
//     };
//     struct work *w = xmalloc(sizeof(struct work));
//     w->e = root;
//     w->in_or = 0;
//     ptrarray_push(&todo, w);
//     while ((w = ptrarray_pop(&todo))) {
//         if (w->e->op == SEOP_MATCH) {
//             if (!strcmp(w->e->attr->name, "jmap_folders") &&
//                 w->e->attr->data1 == 0 &&
//                 strarray_size((strarray_t*)w->e->value.rock) == 1) {
//                 /* Its's an inMailboxId expression */
//                 if (w->in_or || !found_and_match) {
//                     char *folder = strarray_pop((strarray_t*)w->e->value.rock);
//                     _emailsearch_folders_free(&w->e->value);
//                     const search_attr_t *attr = search_attr_find("folder");
//                     w->e->value.s = folder;
//                     w->e->attr = attr;
//                     found_and_match = !w->in_or;
//                 }
//             }
//         }
//         else if (w->e->op == SEOP_AND || w->e->op == SEOP_OR) {
//             search_expr_t *c;
//             for (c = w->e->children; c; c = c->next) {
//                 struct work *ww = xmalloc(sizeof(struct work));
//                 ww->e = c;
//                 ww->in_or = w->in_or || w->e->op == SEOP_OR;
//                 ptrarray_push(&todo, ww);
//             }
//         }
//         free(w);
//     }
//     ptrarray_fini(&todo);

//     return root;
// }

// static void _email_contactfilter_initreq(jmap_req_t *req, struct email_contactfilter *cfilter)
// {
//     const char *addressbookid = json_string_value(json_object_get(req->args, "addressbookId"));
//     jmap_email_contactfilter_init(req->accountid, addressbookid, cfilter);
// }

// static void _email_parse_filter_cb(jmap_req_t *req,
//                                    struct jmap_parser *parser,
//                                    json_t *filter,
//                                    json_t *unsupported,
//                                    void *rock,
//                                    json_t **err)
// {
//     struct email_contactfilter *cfilter = rock;

//     /* Parse filter */
//     jmap_email_filtercondition_parse(parser, filter, unsupported,
//                                      req->using_capabilities);
//     if (json_array_size(parser->invalid)) return;

//     /* Gather contactgroups */
//     int r = jmap_email_contactfilter_from_filtercondition(parser, filter, cfilter);
//     if (r) {
//         *err = jmap_server_error(r);
//         return;
//     }

//     const char *field;
//     json_t *arg;

//     /* Validate permissions */
//     json_object_foreach(filter, field, arg) {
//         if (!strcmp(field, "inMailbox")) {
//             if (json_is_string(arg)) {
//                 const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, json_string_value(arg));
//                 if (!mbentry || !jmap_hasrights(req, mbentry, ACL_LOOKUP)) {
//                     jmap_parser_invalid(parser, field);
//                 }
//             }
//         }
//         else if (!strcmp(field, "inMailboxOtherThan")) {
//             if (json_is_array(arg)) {
//                 size_t i;
//                 json_t *val;
//                 json_array_foreach(arg, i, val) {
//                     const char *s = json_string_value(val);
//                     int is_valid = 0;
//                     if (s) {
//                         const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, s);
//                         is_valid = mbentry && jmap_hasrights(req, mbentry, ACL_LOOKUP);
//                     }
//                     if (!is_valid) {
//                         jmap_parser_push_index(parser, field, i, s);
//                         jmap_parser_invalid(parser, NULL);
//                         jmap_parser_pop(parser);
//                     }
//                 }
//             }
//         }
//     }
// }

// static struct sortcrit *_email_buildsort(json_t *sort, int *sort_savedate)
// {
//     json_t *jcomp;
//     size_t i;
//     struct sortcrit *sortcrit;

//     if (!JNOTNULL(sort) || json_array_size(sort) == 0) {
//         sortcrit = xzmalloc(2 * sizeof(struct sortcrit));
//         sortcrit[0].flags |= SORT_REVERSE;
//         sortcrit[0].key = SORT_ARRIVAL;
//         sortcrit[1].flags |= SORT_REVERSE;
//         sortcrit[1].key = SORT_SEQUENCE;
//         return sortcrit;
//     }

//     sortcrit = xzmalloc((json_array_size(sort) + 1) * sizeof(struct sortcrit));

//     json_array_foreach(sort, i, jcomp) {
//         const char *prop = json_string_value(json_object_get(jcomp, "property"));

//         if (json_object_get(jcomp, "isAscending") == json_false()) {
//             sortcrit[i].flags |= SORT_REVERSE;
//         }

//         /* Note: add any new sort criteria also to is_supported_email_sort */

//         if (!strcmp(prop, "receivedAt")) {
//             sortcrit[i].key = SORT_ARRIVAL;
//         }
//         if (!strcmp(prop, "sentAt")) {
//             sortcrit[i].key = SORT_DATE;
//         }
//         if (!strcmp(prop, "from")) {
//             sortcrit[i].key = SORT_DISPLAYFROM;
//         }
//         if (!strcmp(prop, "id")) {
//             sortcrit[i].key = SORT_GUID;
//         }
//         if (!strcmp(prop, "emailState")) {
//             sortcrit[i].key = SORT_MODSEQ;
//         }
//         if (!strcmp(prop, "size")) {
//             sortcrit[i].key = SORT_SIZE;
//         }
//         if (!strcmp(prop, "subject")) {
//             sortcrit[i].key = SORT_SUBJECT;
//         }
//         if (!strcmp(prop, "to")) {
//             sortcrit[i].key = SORT_DISPLAYTO;
//         }
//         if (!strcmp(prop, "hasKeyword")) {
//             const char *name = json_string_value(json_object_get(jcomp, "keyword"));
//             const char *flagname = jmap_keyword_to_imap(name);
//             if (flagname) {
//                 sortcrit[i].key = SORT_HASFLAG;
//                 sortcrit[i].args.flag.name = xstrdup(flagname);
//             }
//         }
//         if (!strcmp(prop, "someInThreadHaveKeyword")) {
//             const char *name = json_string_value(json_object_get(jcomp, "keyword"));
//             const char *flagname = jmap_keyword_to_imap(name);
//             if (flagname) {
//                 sortcrit[i].key = SORT_HASCONVFLAG;
//                 sortcrit[i].args.flag.name = xstrdup(flagname);
//             }
//         }
//         // FM specific
//         if (!strcmp(prop, "addedDates") || !strcmp(prop, "snoozedUntil")) {
//             const char *mboxid =
//                 json_string_value(json_object_get(jcomp, "mailboxId"));

//             if (sort_savedate) *sort_savedate = 1;
//             sortcrit[i].key = (*prop == 's') ? SORT_SNOOZEDUNTIL : SORT_SAVEDATE;
//             sortcrit[i].args.mailbox.id = xstrdupnull(mboxid);
//         }
//         if (!strcmp(prop, "threadSize")) {
//             sortcrit[i].key = SORT_CONVSIZE;
//         }
//         if (!strcmp(prop, "spamScore")) {
//             sortcrit[i].key = SORT_SPAMSCORE;
//         }
//     }

//     i = json_array_size(sort);
//     sortcrit[i].key = SORT_SEQUENCE;

//     return sortcrit;
// }

// static void _email_querychanges_added(struct jmap_querychanges *query,
//                                       const char *email_id)
// {
//     json_t *item = json_pack("{s:s,s:i}", "id", email_id, "index", query->total-1);
//     json_array_append_new(query->added, item);
// }

// static void _email_querychanges_destroyed(struct jmap_querychanges *query,
//                                           const char *email_id)
// {
//     json_array_append_new(query->removed, json_string(email_id));
// }

// struct emailsearch {
//     int is_mutable;
//     char *hash;
//     strarray_t perf_filters;
//     /* Internal state */
//     search_query_t *query;
//     struct searchargs *args;
//     struct index_state *state;
//     struct sortcrit *sortcrit;
//     struct index_init init;
//     ptrarray_t *cached_msgdata;
// };

// static void _emailsearch_free(struct emailsearch *search)
// {
//     if (!search) return;

//     index_close(&search->state);
//     search_query_free(search->query);
//     freesearchargs(search->args);
//     freesortcrit(search->sortcrit);
//     free(search->hash);
//     strarray_fini(&search->perf_filters);
//     free(search);
// }

// static char *_emailsearch_hash(struct emailsearch *search)
// {
//     struct buf buf = BUF_INITIALIZER;
//     if (search->args->root) {
//         search_expr_t *mysearch = search_expr_duplicate(search->args->root);
//         search_expr_normalise(&mysearch);
//         char *tmp = search_expr_serialise(mysearch);
//         buf_appendcstr(&buf, tmp);
//         free(tmp);
//         search_expr_free(mysearch);
//     }
//     else {
//         buf_appendcstr(&buf, "noquery");
//     }
//     if (search->query->sortcrit) {
//         char *tmp = sortcrit_as_string(search->query->sortcrit);
//         buf_appendcstr(&buf, tmp);
//         free(tmp);
//     }
//     else {
//         buf_appendcstr(&buf, "nosort");
//     }
//     unsigned char raw_sha1[SHA1_DIGEST_LENGTH];
//     xsha1((const unsigned char *) buf_base(&buf), buf_len(&buf), raw_sha1);
//     size_t hex_size = (SHA1_DIGEST_LENGTH << 1);
//     char hex_sha1[hex_size + 1];
//     bin_to_lchex(raw_sha1, SHA1_DIGEST_LENGTH, hex_sha1);
//     hex_sha1[hex_size] = '\0';
//     buf_free(&buf);
//     return xstrdup(hex_sha1);
// }

// #define FNAME_EMAILSEARCH_DB "/jmap_emailsearch.db"
// #define EMAILSEARCH_DB "twoskip"

// static char *emailsearch_getcachepath(void)
// {
//     return xstrdupnull(config_getstring(IMAPOPT_JMAP_EMAILSEARCH_DB_PATH));
// }

// static int _jmap_checkfolder(const char *mboxname, void *rock)
// {
//     jmap_req_t *req = (jmap_req_t *)rock;

//     // we only want to look in folders that the user is allowed to read
//     if (jmap_hasrights_byname(req, mboxname, ACL_READ))
//         return 1;

//     return 0;
// }

// static struct emailsearch* _emailsearch_new(jmap_req_t *req,
//                                             json_t *filter,
//                                             json_t *sort,
//                                             hash_table *contactgroups,
//                                             int want_expunged,
//                                             int ignore_timer,
//                                             int *sort_savedate)
// {
//     struct emailsearch* search = xzmalloc(sizeof(struct emailsearch));
//     int r = 0;

//     /* Build search args */
//     search->args = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
//             &jmap_namespace, req->accountid, req->authstate, 0);
//     search->args->root = _email_buildsearch(req, filter, contactgroups, &search->perf_filters);

//     /* Build index state */
//     search->init.userid = req->accountid;
//     search->init.authstate = req->authstate;
//     search->init.want_expunged = want_expunged;
//     search->init.examine_mode = 1;

//     char *inboxname = mboxname_user_mbox(req->accountid, NULL);
//     r = index_open(inboxname, &search->init, &search->state);
//     free(inboxname);
//     if (r) {
//         syslog(LOG_ERR, "jmap: _emailsearch_new: %s", error_message(r));
//         freesearchargs(search->args);
//         free(search);
//         return NULL;
//     }

//     /* Build query */
//     search->query = search_query_new(search->state, search->args);
//     search->query->sortcrit =
//         search->sortcrit = _email_buildsort(sort, sort_savedate);
//     search->query->multiple = 1;
//     search->query->need_ids = 1;
//     search->query->verbose = 0;
//     search->query->want_expunged = want_expunged;
//     search->query->ignore_timer = ignore_timer;
//     search->query->checkfolder = _jmap_checkfolder;
//     search->query->checkfolderrock = req;
//     search->query->attachments_in_any = jmap_is_using(req, JMAP_SEARCH_EXTENSION);
//     search->is_mutable = search_is_mutable(search->sortcrit, search->args);

//     /* Make hash */
//     search->hash = _emailsearch_hash(search);

//     return search;
// }

// static int _emailsearch_run(struct emailsearch *search, const ptrarray_t **msgdataptr)
// {
//     int r = search_query_run(search->query);
//     if (r) {
//         syslog(LOG_ERR, "jmap: _emailsearch_run: %s", error_message(r));
//         return r;
//     }
//     *msgdataptr = &search->query->merged_msgdata;
//     return 0;
// }

// static int _email_parse_comparator(jmap_req_t *req,
//                                    struct jmap_comparator *comp,
//                                    void *rock __attribute__((unused)),
//                                    json_t **err __attribute__((unused)))
// {
//     /* Reject any collation */
//     if (comp->collation) {
//         return 0;
//     }

//     /* Search in list of supported sortFields */
//     struct email_sortfield *sp = email_sortfields;
//     for (sp = email_sortfields; sp->name; sp++) {
//         if (!strcmp(sp->name, comp->property)) {
//             return !sp->capability || jmap_is_using(req, sp->capability);
//         }
//     }

//     return 0;
// }

// static char *_email_make_querystate(modseq_t modseq, uint32_t uid, modseq_t addrbook_modseq)
// {
//     struct buf buf = BUF_INITIALIZER;
//     buf_printf(&buf, MODSEQ_FMT ":%u", modseq, uid);
//     if (addrbook_modseq) {
//         buf_printf(&buf, ",addrbook:" MODSEQ_FMT, addrbook_modseq);
//     }
//     return buf_release(&buf);
// }

// static int _email_read_querystate(const char *s, modseq_t *modseq, uint32_t *uid,
//                                   modseq_t *addrbook_modseq)
// {
//     char sentinel = 0;

//     /* Parse mailbox modseq and uid */
//     int n = sscanf(s, MODSEQ_FMT ":%u%c", modseq, uid, &sentinel);
//     if (n <= 2) return n == 2;
//     else if (sentinel != ',') return 0;

//     /* Parse addrbook modseq */
//     s = strchr(s, ',') + 1;
//     if (strncmp(s, "addrbook:", 9)) return 0;
//     s += 9;
//     n = sscanf(s, MODSEQ_FMT "%c", addrbook_modseq, &sentinel);
//     if (n != 1) return 0;

//     /* Parsed successfully */
//     return 1;
// }

// struct cached_emailquery {
//     char *ids;         /* zero-terminated id strings */
//     size_t ids_count;  /* count of ids in ids array */
//     size_t id_size;    /* byte-length of an id, excluding 0 byte */
// };

// #define _CACHED_EMAILQUERY_INITIALIZER { NULL, 0, 0 }

// static void _cached_emailquery_fini(struct cached_emailquery *cache_record)
// {
//     free(cache_record->ids);
// }

// #define _EMAILSEARCH_CACHE_VERSION 0x2

// static int _email_query_writecache(struct db *cache_db,
//                                    const char *cache_key,
//                                    modseq_t current_modseq,
//                                    strarray_t *email_ids)
// {
//     int r = 0;

//     /* Serialise cache record preamble */
//     struct buf buf = BUF_INITIALIZER;
//     buf_appendbit32(&buf, _EMAILSEARCH_CACHE_VERSION);
//     buf_appendbit64(&buf, current_modseq);
//     /* Serialise email ids */
//     buf_appendbit64(&buf, strarray_size(email_ids));
//     if (strarray_size(email_ids)) {
//         const char *email_id = strarray_nth(email_ids, 0);
//         size_t email_id_len = strlen(email_id);
//         buf_appendbit64(&buf, email_id_len);
//         int i;
//         for (i = 0; i < strarray_size(email_ids); i++) {
//             const char *email_id = strarray_nth(email_ids, i);
//             if (strlen(email_id) != email_id_len) {
//                 syslog(LOG_ERR, "jmap: email id %s has length %zd,"
//                                 "expected %zd - aborting cache",
//                                 email_id, strlen(email_id), email_id_len);
//                 r = CYRUSDB_INTERNAL;
//                 goto done;
//             }
//             buf_appendcstr(&buf, email_id);
//             buf_putc(&buf, '\0');
//         }
//     }
//     /* Store cache record */
//     r = cyrusdb_store(cache_db, cache_key, strlen(cache_key),
//             buf_base(&buf), buf_len(&buf), NULL);

// done:
//     buf_free(&buf);
//     return r;
// }

// static int _email_query_readcache(struct db *cache_db,
//                                   const char *cache_key,
//                                   modseq_t current_modseq,
//                                   struct cached_emailquery *cache_record)
// {
//     /* Load cache record */
//     const char *data = NULL;
//     size_t datalen = 0;
//     int r = cyrusdb_fetch(cache_db, cache_key, strlen(cache_key), &data, &datalen, NULL);
//     if (r) {
//         if (r != CYRUSDB_NOTFOUND) {
//             syslog(LOG_ERR, "jmap: can't fetch cached email search (%s): %s",
//                     cache_key, cyrusdb_strerror(r));
//         }
//         return r;
//     }

//     /* Read cache record preamble */
//     const char *p = data;
//     uint32_t version = ntohl(((bit32*)(p))[0]); p += 4;
//     if (version != _EMAILSEARCH_CACHE_VERSION) {
//         syslog(LOG_ERR, "jmap: unexpected cache version %d (%s)", version, cache_key);
//         r = CYRUSDB_EXISTS;
//         goto done;
//     }
//     modseq_t cached_modseq = ntohll(((bit64*)(p))[0]); p += 8;
//     if (cached_modseq != current_modseq) {
//         r = CYRUSDB_EXISTS;
//         goto done;
//     }

//     /* Read email ids */
//     size_t ids_count = ntohll(((bit64*)(p))[0]); p += 8;
//     cache_record->ids_count= ids_count;
//     if (ids_count) {
//         size_t id_size = ntohll(((bit64*)(p))[0]); p += 8;
//         cache_record->id_size = id_size;
//         size_t ids_size = ids_count * (id_size + 1);
//         cache_record->ids = xmalloc(ids_size);
//         memcpy(cache_record->ids, p, ids_size);
//         p += ids_size;
//     }

//     /* Check end of record */
//     if (p != data + datalen) {
//         syslog(LOG_ERR, "jmap: invalid query cache entry %s", cache_key);
//         r = CYRUSDB_NOTFOUND;
//         goto done;
//     }

// done:
//     if (r) {
//         _cached_emailquery_fini(cache_record);
//         cyrusdb_delete(cache_db, cache_key, strlen(cache_key), NULL, 0);
//         return r == CYRUSDB_EXISTS? CYRUSDB_NOTFOUND : r;
//     }
//     return 0;
// }

// static void _email_query(jmap_req_t *req, struct jmap_query *query,
//                          int collapse_threads,
//                          hash_table *contactgroups,
//                          json_t **jemailpartids, json_t **err)
// {
//     char *cache_fname = NULL;
//     char *cache_key = NULL;
//     struct db *cache_db = NULL;
//     modseq_t current_modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
//     int is_cached = 0;

//     struct emailsearch *search = _emailsearch_new(req, query->filter, query->sort,
//                                                   contactgroups, 0, 0,
//                                                   &query->sort_savedate);
//     if (!search) {
//         *err = jmap_server_error(IMAP_INTERNAL);
//         goto done;
//     }

//     /* can calculate changes for mutable sort, but not mutable search */
//     query->can_calculate_changes = search->is_mutable > 1 ? 0 : 1;

//     /* make query state */
//     query->query_state = _email_make_querystate(current_modseq, 0,
//             contactgroups->size ?  jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK) : 0);

//     /* Open cache */
//     cache_fname = emailsearch_getcachepath();
//     if (cache_fname) {
//         int flags = CYRUSDB_CREATE|CYRUSDB_CONVERT;
//         int r = cyrusdb_open(EMAILSEARCH_DB, cache_fname, flags, &cache_db);
//         if (r) {
//             syslog(LOG_WARNING, "jmap: can't open email search cache %s: %s",
//                     cache_fname, cyrusdb_strerror(r));
//         }
//     }

//     /* Make cache key */
//     cache_key = strconcat(req->accountid,
//             "/", collapse_threads ?  "collapsed" : "uncollapsed",
//             "/", search->hash, NULL
//     );

//     /* Lookup cache */
//     if (cache_db) {
//         struct cached_emailquery cache_record = _CACHED_EMAILQUERY_INITIALIZER;
//         int r = _email_query_readcache(cache_db, cache_key, current_modseq, &cache_record);
//         if (!r) {
//             size_t from = query->position;
//             if (query->anchor) {
//                 size_t i;
//                 for (i = 0; i < cache_record.ids_count; i++) {
//                     const char *email_id = cache_record.ids + i * (cache_record.id_size + 1);
//                     if (!strcmp(email_id, query->anchor)) {
//                         if (query->anchor_offset < 0) {
//                             size_t neg_offset = (size_t) -query->anchor_offset;
//                             from = neg_offset < i ? i - neg_offset : 0;
//                         }
//                         else {
//                             from = i + query->anchor_offset;
//                         }
//                         break;
//                     }
//                 }
//                 if (i == cache_record.ids_count) {
//                     *err = json_pack("{s:s}", "type", "anchorNotFound");
//                 }
//             }
//             else if (query->position < 0) {
//                 ssize_t sposition = (ssize_t) cache_record.ids_count + query->position;
//                 from = sposition < 0 ? 0 : sposition;
//             }
//             size_t to = query->limit ? from + query->limit : cache_record.ids_count;
//             if (to > cache_record.ids_count) to = cache_record.ids_count;
//             size_t i;
//             for (i = from; i < to; i++) {
//                 const char *email_id = cache_record.ids + i * (cache_record.id_size + 1);
//                 json_array_append_new(query->ids, json_string(email_id));
//             }
//             query->result_position = from;
//             query->total = cache_record.ids_count;
//             is_cached = 1;
//         }
//         _cached_emailquery_fini(&cache_record);
//     }

//     /* Set performance info */
//     if (jmap_is_using(req, JMAP_PERFORMANCE_EXTENSION)) {
//         json_object_set_new(req->perf_details, "isCached", json_boolean(is_cached));
//         int i;
//         json_t *jfilters = json_array();
//         for (i = 0; i < strarray_size(&search->perf_filters); i++) {
//             const char *cost = strarray_nth(&search->perf_filters, i);
//             json_array_append_new(jfilters, json_string(cost));
//         }
//         json_object_set_new(req->perf_details, "filters", jfilters);
//     }
//     if (is_cached) goto done;

//     /* Run search */
//     const ptrarray_t *msgdata = NULL;
//     int r = _emailsearch_run(search, &msgdata);
//     if (r) {
//         *err = jmap_server_error(r);
//         goto done;
//     }

//     // TODO cache emailId -> threadId on the request context
//     // TODO support negative positions
//     assert(query->position >= 0);

//     /* Initialize search result loop */
//     size_t anchor_position = (size_t)-1;
//     char email_id[JMAP_EMAILID_SIZE];

//     struct hashset *seen_emails = hashset_new(12);
//     struct hashset *seen_threads = hashset_new(8);
//     struct hashset *savedates = NULL;

//     /* List of all matching email ids */
//     strarray_t email_ids = STRARRAY_INITIALIZER;

//     int found_anchor = 0;

//     if (query->sort_savedate) {
//         /* Build hashset of messages with savedates */
//         int j;

//         savedates = hashset_new(12);

//         for (j = 0; j < msgdata->count; j++) {
//             MsgData *md = ptrarray_nth(msgdata, j);

//             /* Skip expunged or hidden messages */
//             if (md->system_flags & FLAG_DELETED ||
//                 md->internal_flags & FLAG_INTERNAL_EXPUNGED)
//                 continue;

//             if (md->savedate) hashset_add(savedates, &md->guid.value);
//         }
//     }

//     int i;
//     for (i = 0 ; i < msgdata->count; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         /* Skip expunged or hidden messages */
//         if (md->system_flags & FLAG_DELETED ||
//             md->internal_flags & FLAG_INTERNAL_EXPUNGED)
//             continue;

//         /* Is there another copy of this message with a targeted savedate? */
//         if (!md->savedate &&
//             savedates && hashset_exists(savedates, &md->guid.value))
//             continue;

//         /* Have we seen this message already? */
//         if (!hashset_add(seen_emails, &md->guid.value))
//             continue;
//         if (collapse_threads && !hashset_add(seen_threads, &md->cid))
//             continue;

//         /* This message matches the query. */
//         size_t result_count = json_array_size(query->ids);
//         query->total++;
//         jmap_set_emailid(&md->guid, email_id);

//         if (cache_db) strarray_append(&email_ids, email_id);

//         /* Apply query window, if any */
//         if (query->anchor) {
//             if (!strcmp(email_id, query->anchor)) {
//                 found_anchor = 1;
//                 /* Recalculate the search result */
//                 json_t *anchored_ids = json_pack("[]");
//                 size_t j;
//                 /* Set countdown to enter the anchor window */
//                 if (query->anchor_offset > 0) {
//                     anchor_position = query->anchor_offset;
//                 } else {
//                     anchor_position = 0;
//                 }
//                 /* Readjust the result list */
//                 if (query->anchor_offset < 0) {
//                     size_t neg_offset = (size_t) -query->anchor_offset;
//                     size_t from = neg_offset < result_count ? result_count - neg_offset : 0;
//                     for (j = from; j < result_count; j++) {
//                         json_array_append(anchored_ids, json_array_get(query->ids, j));
//                     }
//                 }
//                 json_decref(query->ids);
//                 query->ids = anchored_ids;
//                 result_count = json_array_size(query->ids);

//                 /* Adjust the window position for this anchor. */
//                 query->result_position = query->total - json_array_size(anchored_ids) - 1;
//             }
//             if (anchor_position != (size_t)-1 && anchor_position) {
//                 /* Found the anchor but haven't yet entered its window */
//                 anchor_position--;
//                 /* But this message still counts to the window position */
//                 query->result_position++;
//                 continue;
//             }
//         }
//         else if (query->position > 0 && query->total < ((size_t) query->position) + 1) {
//             continue;
//         }

//         /* Apply limit */
//         if (query->limit && result_count && query->limit <= result_count)
//             continue;

//         /* Add message to result */
//         json_array_append_new(query->ids, json_string(email_id));
//         if (*jemailpartids == NULL) {
//             *jemailpartids = json_object();
//         }
//         if (md->folder && md->folder->partids.size) {
//             const strarray_t *partids = hashu64_lookup(md->uid, &md->folder->partids);
//             if (partids && strarray_size(partids)) {
//                 json_t *jpartids = json_array();
//                 int k;
//                 for (k = 0; k < strarray_size(partids); k++) {
//                     const char *partid = strarray_nth(partids, k);
//                     json_array_append_new(jpartids, json_string(partid));
//                 }
//                 json_object_set_new(*jemailpartids, email_id, jpartids);
//             }
//         }
//         if (!json_object_get(*jemailpartids, email_id)) {
//             json_object_set_new(*jemailpartids, email_id, json_null());
//         }
//     }
//     hashset_free(&seen_threads);
//     hashset_free(&seen_emails);
//     if (savedates) hashset_free(&savedates);

//     if (!query->anchor) {
//         query->result_position = query->position;
//     }
//     else if (!found_anchor) {
//         *err = json_pack("{s:s}", "type", "anchorNotFound");
//     }

//     /* Cache search result */
//     if (cache_db) {
//         int r = _email_query_writecache(cache_db, cache_key, current_modseq, &email_ids);
//         if (r) {
//             syslog(LOG_ERR, "jmap: can't cache email search (%s): %s",
//                     cache_key, cyrusdb_strerror(r));
//             r = 0;
//         }
//     }
//     strarray_fini(&email_ids);

//     if (jemailpartids && !*jemailpartids)
//         *jemailpartids = json_null();

// done:
//     _emailsearch_free(search);
//     if (cache_db) {
//         int r = cyrusdb_close(cache_db);
//         if (r) {
//             syslog(LOG_ERR, "jmap: can't close email search cache %s: %s",
//                     cache_fname, cyrusdb_strerror(r));
//         }
//     }
//     free(cache_key);
//     free(cache_fname);
// }

// static int _email_queryargs_parse(jmap_req_t *req,
//                                   struct jmap_parser *parser __attribute__((unused)),
//                                   const char *key,
//                                   json_t *arg,
//                                   void *rock)
// {
//     int *collapse_threads = (int *) rock;
//     int r = 1;

//     if (!strcmp(key, "collapseThreads") && json_is_boolean(arg)) {
//         *collapse_threads = json_boolean_value(arg);
//     }
//     else if (!strcmp(key, "addressbookId") && json_is_string(arg) &&
//              jmap_is_using(req, JMAP_MAIL_EXTENSION)) {

//         /* Lookup addrbook */
//         char *addrbookname = carddav_mboxname(req->accountid, json_string_value(arg));
//         mbentry_t *mbentry = NULL;
//         int is_valid = 0;
//         if (!mboxlist_lookup(addrbookname, &mbentry, NULL)) {
//             is_valid = jmap_hasrights(req, mbentry, ACL_LOOKUP) &&
//                        mbentry->mbtype == MBTYPE_ADDRESSBOOK;
//         }
//         mboxlist_entry_free(&mbentry);
//         free(addrbookname);
//         return is_valid;
//     }
//     else r = 0;

//     return r;
// }

// static int jmap_email_query(jmap_req_t *req)
// {
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct jmap_query query;
//     int collapse_threads = 0;
//     json_t *jemailpartids = NULL;
//     struct email_contactfilter contactfilter;
//     int r = 0;

//     _email_contactfilter_initreq(req, &contactfilter);

//     /* Parse request */
//     json_t *err = NULL;
//     jmap_query_parse(req, &parser,
//                      _email_queryargs_parse, &collapse_threads,
//                      _email_parse_filter_cb, &contactfilter,
//                      _email_parse_comparator, NULL,
//                      &query, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }
//     if (query.position < 0) {
//         /* we currently don't support negative positions */
//         jmap_parser_invalid(&parser, "position");
//     }
//     if (json_array_size(parser.invalid)) {
//         err = json_pack("{s:s}", "type", "invalidArguments");
//         json_object_set(err, "arguments", parser.invalid);
//         jmap_error(req, err);
//         goto done;
//     }
//     else if (r) {
//         jmap_error(req, jmap_server_error(r));
//         goto done;
//     }

//     /* Run query */
//     _email_query(req, &query, collapse_threads, &contactfilter.contactgroups,
//                  &jemailpartids, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Build response */
//     json_t *res = jmap_query_reply(&query);
//     json_object_set(res, "collapseThreads", json_boolean(collapse_threads));
//     if (jmap_is_using(req, JMAP_SEARCH_EXTENSION)) {
//         json_object_set(res, "partIds", jemailpartids); // incref
//     }
//     if (jmap_is_using(req, JMAP_DEBUG_EXTENSION)) {
//         /* List language stats */
//         const struct search_engine *engine = search_engine();
//         if (engine->list_lang_stats) {
//             ptrarray_t lstats = PTRARRAY_INITIALIZER;
//             int r = engine->list_lang_stats(req->accountid, &lstats);
//             if (!r) {
//                 json_t *jstats = json_object();
//                 struct search_lang_stats *lstat;
//                 while ((lstat = ptrarray_pop(&lstats))) {
//                     json_t *jstat = json_pack("{s:f}", "weight", lstat->weight);
//                     json_object_set_new(jstats, lstat->iso_lang, jstat);
//                     free(lstat->iso_lang);
//                     free(lstat);
//                 }
//                 json_object_set_new(res, "languageStats", jstats);
//             }
//             ptrarray_fini(&lstats);
//         }
//     }
//     jmap_ok(req, res);

// done:
//     jmap_email_contactfilter_fini(&contactfilter);
//     json_decref(jemailpartids);
//     jmap_query_fini(&query);
//     jmap_parser_fini(&parser);
//     return 0;
// }

// static void _email_querychanges_collapsed(jmap_req_t *req,
//                                           struct jmap_querychanges *query,
//                                           struct email_contactfilter *contactfilter,
//                                           json_t **err)
// {
//     modseq_t since_modseq;
//     uint32_t since_uid;
//     uint32_t num_changes = 0;
//     modseq_t addrbook_modseq = 0;

//     if (!_email_read_querystate(query->since_querystate,
//                                 &since_modseq, &since_uid,
//                                 &addrbook_modseq)) {
//         *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
//         return;
//     }
//     if (addrbook_modseq && addrbook_modseq != jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK)) {
//         *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
//         return;
//     }

//     struct emailsearch *search = _emailsearch_new(req, query->filter, query->sort,
//                                                   &contactfilter->contactgroups,
//                                                   /*want_expunged*/1, /*ignore_timer*/0,
//                                                   &query->sort_savedate);
//     if (!search) {
//         *err = jmap_server_error(IMAP_INTERNAL);
//         goto done;
//     }

//     /* Run search */
//     const ptrarray_t *msgdata = NULL;
//     int r = _emailsearch_run(search, &msgdata);
//     if (r) {
//         if (r == IMAP_SEARCH_SLOW) {
//             *err = json_pack("{s:s, s:s}", "type", "cannotCalculateChanges",
//                                            "description", "search too slow");
//         }
//         else {
//             *err = jmap_server_error(r);
//         }
//         goto done;
//     }

//     /* Prepare result loop */
//     char email_id[JMAP_EMAILID_SIZE];
//     int found_up_to = 0;
//     size_t mdcount = msgdata->count;

//     hash_table touched_ids = HASH_TABLE_INITIALIZER;
//     memset(&touched_ids, 0, sizeof(hash_table));
//     construct_hash_table(&touched_ids, mdcount + 1, 0);

//     hashu64_table touched_cids = HASH_TABLE_INITIALIZER;
//     memset(&touched_cids, 0, sizeof(hashu64_table));
//     construct_hashu64_table(&touched_cids, mdcount + 1, 0);

//     /* touched_ids contains values for each email_id:
//      * 1 - email has been modified
//      * 2 - email has been seen (aka: non-expunged record shown)
//      * 4 - email has been reported removed
//      * 8 - email has been reported added
//      */

//     /* touched_cids contains values for each thread
//      * 1 - thread has been modified
//      * 2 - thread has been seen (aka: exemplar shown)
//      * 4 - thread has had an expunged shown (aka: possible old exemplar passed)
//      * 8 - thread is finished (aka: old exemplar definitely passed)
//      */

//     // phase 1: find messages and threads which have been modified
//     size_t i;
//     for (i = 0 ; i < mdcount; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         // for this phase, we only care that it has a change
//         if (md->modseq <= since_modseq) {
//             if (search->is_mutable) {
//                 modseq_t modseq = 0;
//                 conversation_get_modseq(req->cstate, md->cid, &modseq);
//                 if (modseq > since_modseq)
//                     hashu64_insert(md->cid, (void*)1, &touched_cids);
//             }
//             continue;
//         }

//         jmap_set_emailid(&md->guid, email_id);

//         hash_insert(email_id, (void*)1, &touched_ids);
//         hashu64_insert(md->cid, (void*)1, &touched_cids);
//     }

//     // phase 2: report messages that need it
//     for (i = 0 ; i < mdcount; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         jmap_set_emailid(&md->guid, email_id);

//         int is_expunged = (md->system_flags & FLAG_DELETED) ||
//                 (md->internal_flags & FLAG_INTERNAL_EXPUNGED);

//         size_t touched_id = (size_t)hash_lookup(email_id, &touched_ids);
//         size_t new_touched_id = touched_id;

//         size_t touched_cid = (size_t)hashu64_lookup(md->cid, &touched_cids);
//         size_t new_touched_cid = touched_cid;

//         if (is_expunged) {
//             // don't need to tell changes any more
//             if (found_up_to) goto doneloop;

//             // nothing to do if not changed (could not be old exemplar)
//             if (!(touched_id & 1)) goto doneloop;

//             // could not possibly be old exemplar
//             if (!search->is_mutable && (touched_cid & 8)) goto doneloop;

//             // add the destroy notice
//             if (!(touched_id & 4)) {
//                 _email_querychanges_destroyed(query, email_id);
//                 new_touched_id |= 4;
//                 new_touched_cid |= 4;
//             }

//             goto doneloop;
//         }

//         // this is the exemplar for the cid
//         if (!(touched_cid & 2)) {
//             query->total++;
//             new_touched_cid |= 2;
//         }

//         if (found_up_to) goto doneloop;

//         // if it's a changed cid, see if we should tell
//         if ((touched_cid & 1)) {
//             // haven't told the exemplar yet?  This is the exemplar!
//             if (!(touched_cid & 2)) {
//                 // not yet told in any way, and this ID hasn't been told at all
//                 if (touched_cid == 1 && touched_id == 0 && !search->is_mutable) {
//                     // this is both old AND new exemplar, horray.  We don't
//                     // need to tell anything
//                     new_touched_cid |= 8;
//                     goto doneloop;
//                 }

//                 // have to tell both a remove and an add for the exemplar
//                 if (!(touched_id & 4)) {
//                     _email_querychanges_destroyed(query, email_id);
//                     new_touched_id |= 4;
//                     num_changes++;
//                 }
//                 if (!(touched_id & 8)) {
//                     _email_querychanges_added(query, email_id);
//                     new_touched_id |= 8;
//                     num_changes++;
//                 }
//                 new_touched_cid |= 4;
//                 goto doneloop;
//             }
//             // otherwise we've already told the exemplar.

//             // could not possibly be old exemplar
//             if (!search->is_mutable && (touched_cid & 8)) goto doneloop;

//             // OK, maybe this alive message WAS the old examplar
//             if (!(touched_id & 4)) {
//                 _email_querychanges_destroyed(query, email_id);
//                 new_touched_id |= 4;
//                 new_touched_cid |= 4;
//             }

//             // and if this message is a stopper (must have been a candidate
//             // for old exemplar) then stop
//             if (!(touched_id & 1)) {
//                 new_touched_cid |= 8;
//             }
//         }

//     doneloop:
//         if (query->max_changes && (num_changes > query->max_changes)) {
//             *err = json_pack("{s:s}", "type", "tooManyChanges");
//             break;
//         }
//         if (new_touched_id != touched_id)
//             hash_insert(email_id, (void*)new_touched_id, &touched_ids);
//         if (new_touched_cid != touched_cid)
//             hashu64_insert(md->cid, (void*)new_touched_cid, &touched_cids);
//         // if the search is mutable, later changes could have
//         // been earlier once, so no up_to_id is possible
//         if (!found_up_to && !search->is_mutable
//                          && query->up_to_id
//                          && !strcmp(email_id, query->up_to_id)) {
//             found_up_to = 1;
//         }
//     }

//     free_hash_table(&touched_ids, NULL);
//     free_hashu64_table(&touched_cids, NULL);

//     modseq_t modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
//     query->new_querystate = _email_make_querystate(modseq, 0, addrbook_modseq);

// done:
//     _emailsearch_free(search);
// }

// static void _email_querychanges_uncollapsed(jmap_req_t *req,
//                                             struct jmap_querychanges *query,
//                                             struct email_contactfilter *contactfilter,
//                                             json_t **err)
// {
//     modseq_t since_modseq;
//     uint32_t since_uid;
//     uint32_t num_changes = 0;
//     modseq_t addrbook_modseq = 0;

//     if (!_email_read_querystate(query->since_querystate,
//                                 &since_modseq, &since_uid,
//                                 &addrbook_modseq)) {
//         *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
//         return;
//     }
//     if (addrbook_modseq && addrbook_modseq != jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK)) {
//         *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
//         return;
//     }

//     struct emailsearch *search = _emailsearch_new(req, query->filter, query->sort,
//                                                   &contactfilter->contactgroups,
//                                                   /*want_expunged*/1, /*ignore_timer*/0,
//                                                   &query->sort_savedate);
//     if (!search) {
//         *err = jmap_server_error(IMAP_INTERNAL);
//         goto done;
//     }

//     /* Run search */
//     const ptrarray_t *msgdata = NULL;
//     int r = _emailsearch_run(search, &msgdata);
//     if (r) {
//         if (r == IMAP_SEARCH_SLOW) {
//             *err = json_pack("{s:s, s:s}", "type", "cannotCalculateChanges",
//                                            "description", "search too slow");
//         }
//         else {
//             *err = jmap_server_error(r);
//         }
//         goto done;
//     }

//     /* Prepare result loop */
//     char email_id[JMAP_EMAILID_SIZE];
//     int found_up_to = 0;
//     size_t mdcount = msgdata->count;

//     hash_table touched_ids = HASH_TABLE_INITIALIZER;
//     memset(&touched_ids, 0, sizeof(hash_table));
//     construct_hash_table(&touched_ids, mdcount + 1, 0);

//     /* touched_ids contains values for each email_id:
//      * 1 - email has been modified
//      * 2 - email has been seen (aka: non-expunged record shown)
//      * 4 - email has been reported removed
//      * 8 - email has been reported added
//      */

//     // phase 1: find messages which have been modified
//     size_t i;
//     for (i = 0 ; i < mdcount; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         // for this phase, we only care that it has a change
//         if (md->modseq <= since_modseq) continue;

//         jmap_set_emailid(&md->guid, email_id);

//         hash_insert(email_id, (void*)1, &touched_ids);
//     }

//     // phase 2: report messages that need it
//     for (i = 0 ; i < mdcount; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         jmap_set_emailid(&md->guid, email_id);

//         int is_expunged = (md->system_flags & FLAG_DELETED) ||
//                 (md->internal_flags & FLAG_INTERNAL_EXPUNGED);

//         size_t touched_id = (size_t)hash_lookup(email_id, &touched_ids);
//         size_t new_touched_id = touched_id;

//         if (is_expunged) {
//             // don't need to tell changes any more
//             if (found_up_to) continue;

//             // nothing to do if not changed
//             if (!(touched_id & 1)) continue;

//             // add the destroy notice
//             if (!(touched_id & 4)) {
//                 _email_querychanges_destroyed(query, email_id);
//                 new_touched_id |= 4;
//             }

//             goto doneloop;
//         }

//         // this is an exemplar
//         if (!(touched_id & 2)) {
//             query->total++;
//             new_touched_id |= 2;
//         }

//         if (found_up_to) goto doneloop;

//         // if it's changed, tell about that
//         if ((touched_id & 1)) {
//             if (!search->is_mutable && touched_id == 1 && md->modseq <= since_modseq) {
//                 // this is the exemplar, and it's unchanged,
//                 // and we haven't told a removed yet, so we
//                 // can just suppress everything
//                 new_touched_id |= 4 | 8;
//                 goto doneloop;
//             }

//             // otherwise we're going to have to tell both, if we haven't already
//             if (!(touched_id & 4)) {
//                 _email_querychanges_destroyed(query, email_id);
//                 new_touched_id |= 4;
//                 num_changes++;
//             }
//             if (!(touched_id & 8)) {
//                 _email_querychanges_added(query, email_id);
//                 new_touched_id |= 8;
//                 num_changes++;
//             }
//         }

//     doneloop:
//         if (query->max_changes && (num_changes > query->max_changes)) {
//             *err = json_pack("{s:s}", "type", "tooManyChanges");
//             break;
//         }
//         if (new_touched_id != touched_id)
//             hash_insert(email_id, (void*)new_touched_id, &touched_ids);
//         // if the search is mutable, later changes could have
//         // been earlier once, so no up_to_id is possible
//         if (!found_up_to && !search->is_mutable
//                          && query->up_to_id
//                          && !strcmp(email_id, query->up_to_id)) {
//             found_up_to = 1;
//         }
//     }

//     free_hash_table(&touched_ids, NULL);

//     modseq_t modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
//     query->new_querystate = _email_make_querystate(modseq, 0, addrbook_modseq);

// done:
//     _emailsearch_free(search);
// }

// static int jmap_email_querychanges(jmap_req_t *req)
// {
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct jmap_querychanges query;
//     struct email_contactfilter contactfilter;
//     int collapse_threads = 0;

//     _email_contactfilter_initreq(req, &contactfilter);

//     /* Parse arguments */
//     json_t *err = NULL;
//     jmap_querychanges_parse(req, &parser,
//                             _email_queryargs_parse, &collapse_threads,
//                             _email_parse_filter_cb, &contactfilter,
//                             _email_parse_comparator, NULL,
//                             &query, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     if (json_array_size(parser.invalid)) {
//         err = json_pack("{s:s}", "type", "invalidArguments");
//         json_object_set(err, "arguments", parser.invalid);
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Query changes */
//     if (collapse_threads)
//         _email_querychanges_collapsed(req, &query, &contactfilter, &err);
//     else
//         _email_querychanges_uncollapsed(req, &query, &contactfilter, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Build response */
//     json_t *res = jmap_querychanges_reply(&query);
//     json_object_set(res, "collapseThreads", json_boolean(collapse_threads));
//     jmap_ok(req, res);

// done:
//     jmap_email_contactfilter_fini(&contactfilter);
//     jmap_querychanges_fini(&query);
//     jmap_parser_fini(&parser);
//     return 0;
// }

// static void _email_changes(jmap_req_t *req, struct jmap_changes *changes, json_t **err)
// {
//     /* Run search */
//     json_t *filter = json_pack("{s:o}", "sinceEmailState",
//                                jmap_fmtstate(changes->since_modseq));
//     json_t *sort = json_pack("[{s:s}]", "property", "emailState");

//     struct emailsearch *search = _emailsearch_new(req, filter, sort,
//                                                   /*contactgroups*/NULL,
//                                                   /*want_expunged*/1,
//                                                   /*ignore_timer*/1,
//                                                   NULL);
//     if (!search) {
//         *err = jmap_server_error(IMAP_INTERNAL);
//         goto done;
//     }

//     const ptrarray_t *msgdata = NULL;
//     int r = _emailsearch_run(search, &msgdata);
//     if (r) {
//         *err = jmap_server_error(r);
//         goto done;
//     }

//     /* Process results */
//     char email_id[JMAP_EMAILID_SIZE];
//     size_t changes_count = 0;
//     modseq_t highest_modseq = 0;
//     int i;
//     hash_table seen_ids = HASH_TABLE_INITIALIZER;
//     memset(&seen_ids, 0, sizeof(hash_table));
//     construct_hash_table(&seen_ids, msgdata->count + 1, 0);

//     for (i = 0 ; i < msgdata->count; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         jmap_set_emailid(&md->guid, email_id);

//         /* Skip already seen messages */
//         if (hash_lookup(email_id, &seen_ids)) continue;
//         hash_insert(email_id, (void*)1, &seen_ids);

//         /* Apply limit, if any */
//         if (changes->max_changes && ++changes_count > changes->max_changes) {
//             changes->has_more_changes = 1;
//             break;
//         }

//         /* Keep track of the highest modseq */
//         if (highest_modseq < md->modseq)
//             highest_modseq = md->modseq;

//         struct email_expunge_check rock = { req, changes->since_modseq, 0 };
//         int r = conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
//                                            _email_is_expunged_cb, &rock);
//         if (r) {
//             *err = jmap_server_error(r);
//             goto done;
//         }

//         /* Check the message status - status is a bitfield with:
//          * 1: a message exists which was created on or before since_modseq
//          * 2: a message exists which is not deleted
//          *
//          * from those facts we can determine ephemeral / destroyed / created / updated
//          * and we don't need to tell about ephemeral (all created since last time, but none left)
//          */
//         switch (rock.status) {
//         default:
//             break; /* all messages were created AND deleted since previous state! */
//         case 1:
//             /* only expunged messages exist */
//             json_array_append_new(changes->destroyed, json_string(email_id));
//             break;
//         case 2:
//             /* alive, and all messages are created since previous modseq */
//             json_array_append_new(changes->created, json_string(email_id));
//             break;
//         case 3:
//             /* alive, and old */
//             json_array_append_new(changes->updated, json_string(email_id));
//             break;
//         }
//     }
//     free_hash_table(&seen_ids, NULL);

//     /* Set new state */
//     changes->new_modseq = changes->has_more_changes ?
//         highest_modseq : jmap_highestmodseq(req, MBTYPE_EMAIL);

// done:
//     json_decref(filter);
//     json_decref(sort);
//     _emailsearch_free(search);
// }

// static int jmap_email_changes(jmap_req_t *req)
// {
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct jmap_changes changes;

//     /* Parse request */
//     json_t *err = NULL;
//     jmap_changes_parse(req, &parser, NULL, NULL, &changes, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Search for updates */
//     _email_changes(req, &changes, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Build response */
//     jmap_ok(req, jmap_changes_reply(&changes));

// done:
//     jmap_changes_fini(&changes);
//     jmap_parser_fini(&parser);
//     return 0;
// }

// static void _thread_changes(jmap_req_t *req, struct jmap_changes *changes, json_t **err)
// {
//     conversation_t conv = CONVERSATION_INIT;

//     /* Run search */
//     json_t *filter = json_pack("{s:o}", "sinceEmailState",
//                                jmap_fmtstate(changes->since_modseq));
//     json_t *sort = json_pack("[{s:s}]", "property", "emailState");
//     struct emailsearch *search = _emailsearch_new(req, filter, sort,
//                                                   /*contactgroups*/NULL,
//                                                   /*want_expunged*/1,
//                                                   /*ignore_timer*/1,
//                                                   NULL);
//     if (!search) {
//         *err = jmap_server_error(IMAP_INTERNAL);
//         goto done;
//     }

//     const ptrarray_t *msgdata = NULL;
//     int r = _emailsearch_run(search, &msgdata);
//     if (r) {
//         *err = jmap_server_error(r);
//         goto done;
//     }

//     /* Process results */
//     size_t changes_count = 0;
//     modseq_t highest_modseq = 0;
//     int i;

//     struct hashset *seen_threads = hashset_new(8);

//     char thread_id[JMAP_THREADID_SIZE];

//     for (i = 0 ; i < msgdata->count; i++) {
//         MsgData *md = ptrarray_nth(msgdata, i);

//         /* Skip already seen threads */
//         if (!hashset_add(seen_threads, &md->cid)) continue;

//         /* Apply limit, if any */
//         if (changes->max_changes && ++changes_count > changes->max_changes) {
//             changes->has_more_changes = 1;
//             break;
//         }

//         /* Keep track of the highest modseq */
//         if (highest_modseq < md->modseq)
//             highest_modseq = md->modseq;

//         /* Determine if the thread got changed or destroyed */
//         if (conversation_load_advanced(req->cstate, md->cid, &conv, /*flags*/0))
//             continue;

//         /* Report thread */
//         jmap_set_threadid(md->cid, thread_id);
//         if (conv.exists) {
//             if (conv.createdmodseq <= changes->since_modseq)
//                 json_array_append_new(changes->updated, json_string(thread_id));
//             else
//                 json_array_append_new(changes->created, json_string(thread_id));
//         }
//         else {
//             if (conv.createdmodseq <= changes->since_modseq)
//                 json_array_append_new(changes->destroyed, json_string(thread_id));
//         }

//         conversation_fini(&conv);
//         memset(&conv, 0, sizeof(conversation_t));
//     }
//     hashset_free(&seen_threads);

//     /* Set new state */
//     changes->new_modseq = changes->has_more_changes ?
//         highest_modseq : jmap_highestmodseq(req, MBTYPE_EMAIL);

// done:
//     conversation_fini(&conv);
//     json_decref(filter);
//     json_decref(sort);
//     _emailsearch_free(search);
// }

// static int jmap_thread_changes(jmap_req_t *req)
// {
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct jmap_changes changes;

//     /* Parse request */
//     json_t *err = NULL;
//     jmap_changes_parse(req, &parser, NULL, NULL, &changes, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Search for updates */
//     _thread_changes(req, &changes, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Build response */
//     jmap_ok(req, jmap_changes_reply(&changes));

// done:
//     jmap_changes_fini(&changes);
//     jmap_parser_fini(&parser);
//     return 0;
// }

// static int _snippet_get_cb(struct mailbox *mbox __attribute__((unused)),
//                            uint32_t uid __attribute__((unused)),
//                            int part, const char *s, void *rock)
// {
//     const char *propname = NULL;
//     json_t *snippet = rock;

//     if (part == SEARCH_PART_SUBJECT) {
//         propname = "subject";
//     }
//     else if (part == SEARCH_PART_BODY || part == SEARCH_PART_ATTACHMENTBODY) {
//         propname = "preview";
//     }

//     if (propname) {
//         json_object_set_new(snippet, propname, json_string(s));
//     }

//     /* Avoid costly attachment body snippets, if possible */
//     return part == SEARCH_PART_BODY ? IMAP_OK_COMPLETED : 0;
// }

// static int _snippet_get(jmap_req_t *req, json_t *filter,
//                         json_t *messageids, json_t *jemailpartids,
//                         json_t **snippets, json_t **notfound)
// {
//     struct index_state *state = NULL;
//     void *intquery = NULL;
//     search_builder_t *bx = NULL;
//     search_text_receiver_t *rx = NULL;
//     struct mailbox *mbox = NULL;
//     struct searchargs *searchargs = NULL;
//     struct index_init init;
//     json_t *snippet = NULL;
//     int r = 0;
//     json_t *val;
//     size_t i;
//     char *mboxname = NULL;
//     static search_snippet_markup_t markup = { "<mark>", "</mark>", "..." };
//     strarray_t partids = STRARRAY_INITIALIZER;

//     *snippets = json_pack("[]");
//     *notfound = json_pack("[]");

//     /* Build searchargs */
//     strarray_t perf_filters = STRARRAY_INITIALIZER;
//     searchargs = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
//                                 &jmap_namespace, req->userid, req->authstate, 0);
//     searchargs->root = _email_buildsearch(req, filter, /*contactgroups*/NULL, &perf_filters);
//     strarray_fini(&perf_filters);

//     /* Build the search query */
//     memset(&init, 0, sizeof(init));
//     init.userid = req->userid;
//     init.authstate = req->authstate;
//     init.examine_mode = 1;

//     char *inboxname = mboxname_user_mbox(req->accountid, NULL);
//     r = index_open(inboxname, &init, &state);
//     free(inboxname);
//     if (r) goto done;

//     bx = search_begin_search(state->mailbox, SEARCH_MULTIPLE);
//     if (!bx) {
//         r = IMAP_INTERNAL;
//         goto done;
//     }

//     search_build_query(bx, searchargs->root);
//     if (!bx->get_internalised) {
//         r = IMAP_INTERNAL;
//         goto done;
//     }
//     intquery = bx->get_internalised(bx);
//     search_end_search(bx);
//     if (!intquery) {
//         r = IMAP_INTERNAL;
//         goto done;
//     }

//     /* Set up snippet callback context */
//     snippet = json_pack("{}");
//     rx = search_begin_snippets(intquery, 0, &markup, _snippet_get_cb, snippet);
//     if (!rx) {
//         r = IMAP_INTERNAL;
//         goto done;
//     }

//     /* Convert the snippets */
//     json_array_foreach(messageids, i, val) {
//         message_t *msg;
//         msgrecord_t *mr = NULL;
//         uint32_t uid;

//         const char *msgid = json_string_value(val);

//         r = jmap_email_find(req, msgid, &mboxname, &uid);
//         if (r) {
//             if (r == IMAP_NOTFOUND) {
//                 json_array_append_new(*notfound, json_string(msgid));
//             }
//             r = 0;
//             continue;
//         }

//         r = jmap_openmbox(req, mboxname, &mbox, 0);
//         if (r) goto done;

//         r = msgrecord_find(mbox, uid, &mr);
//         if (r) goto doneloop;

//         r = msgrecord_get_message(mr, &msg);
//         if (r) goto doneloop;

//         json_t *jpartids = json_object_get(jemailpartids, msgid);
//         if (jpartids) {
//             json_t *jpartid;
//             size_t j;
//             json_array_foreach(jpartids, j, jpartid) {
//                 strarray_append(&partids, json_string_value(jpartid));
//             }
//         }
//         json_object_set_new(snippet, "emailId", json_string(msgid));
//         json_object_set_new(snippet, "subject", json_null());
//         json_object_set_new(snippet, "preview", json_null());

//         r = rx->begin_mailbox(rx, mbox, /*incremental*/0);
//         r = index_getsearchtext(msg, jpartids ? &partids : NULL, rx, 1);
//         if (!r || r == IMAP_OK_COMPLETED) {
//             json_array_append_new(*snippets, json_deep_copy(snippet));
//             r = 0;
//         }
//         int r2 = rx->end_mailbox(rx, mbox);
//         if (!r) r = r2;

//         json_object_clear(snippet);
//         strarray_truncate(&partids, 0);
//         msgrecord_unref(&mr);

// doneloop:
//         if (mr) msgrecord_unref(&mr);
//         jmap_closembox(req, &mbox);
//         free(mboxname);
//         mboxname = NULL;
//         if (r) goto done;
//     }

//     if (!json_array_size(*notfound)) {
//         json_decref(*notfound);
//         *notfound = json_null();
//     }

// done:
//     if (rx) search_end_snippets(rx);
//     if (snippet) json_decref(snippet);
//     if (intquery) search_free_internalised(intquery);
//     if (mboxname) free(mboxname);
//     if (mbox) jmap_closembox(req, &mbox);
//     if (searchargs) freesearchargs(searchargs);
//     strarray_fini(&partids);
//     index_close(&state);

//     return r;
// }

// static int _email_filter_contains_text(json_t *filter)
// {
//     if (JNOTNULL(filter)) {
//         json_t *val;
//         size_t i;

//         if (JNOTNULL(json_object_get(filter, "text"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "subject"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "body"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "attachmentBody"))) {
//             return 1;
//         }

//         /* We don't generate snippets for headers, but we
//          * might find header text in the body or subject again. */
//         if (JNOTNULL(json_object_get(filter, "header"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "from"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "to"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "cc"))) {
//             return 1;
//         }
//         if (JNOTNULL(json_object_get(filter, "bcc"))) {
//             return 1;
//         }

//         json_array_foreach(json_object_get(filter, "conditions"), i, val) {
//             if (_email_filter_contains_text(val)) {
//                 return 1;
//             }
//         }
//     }
//     return 0;
// }

// static int jmap_searchsnippet_get(jmap_req_t *req)
// {
//     int r = 0;
//     const char *key;
//     json_t *arg, *jfilter = NULL, *jmessageids = NULL, *jemailpartids = NULL;
//     json_t *snippets, *notfound;
//     struct buf buf = BUF_INITIALIZER;
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct email_contactfilter contactfilter;
//     json_t *err = NULL;

//     _email_contactfilter_initreq(req, &contactfilter);

//     /* Parse and validate arguments. */
//     json_t *unsupported_filter = json_pack("[]");

//     json_object_foreach(req->args, key, arg) {
//         if (!strcmp(key, "accountId")) {
//             /* already handled in jmap_api() */
//         }

//         /* filter */
//         else if (!strcmp(key, "filter")) {
//             jfilter = arg;
//             if (JNOTNULL(jfilter)) {
//                 jmap_parser_push(&parser, "filter");
//                 jmap_filter_parse(req, &parser, jfilter, unsupported_filter,
//                                   _email_parse_filter_cb, &contactfilter, &err);
//                 jmap_parser_pop(&parser);
//                 if (err) break;
//             }
//         }

//         /* messageIds */
//         else if (!strcmp(key, "emailIds")) {
//             jmessageids = arg;
//             if (json_array_size(jmessageids)) {
//                 jmap_parse_strings(jmessageids, &parser, "emailIds");
//             }
//             else if (!json_is_array(jmessageids)) {
//                 jmap_parser_invalid(&parser, "emailIds");
//             }
//         }

//         /* partIds */
//         else if (jmap_is_using(req, JMAP_SEARCH_EXTENSION) && !strcmp(key, "partIds")) {
//             jemailpartids = arg;
//             int is_valid = 1;
//             if (json_is_object(jemailpartids)) {
//                 const char *email_id;
//                 json_t *jpartids;
//                 json_object_foreach(jemailpartids, email_id, jpartids) {
//                     if (json_is_array(jpartids)) {
//                         size_t i;
//                         json_t *jpartid;
//                         json_array_foreach(jpartids, i, jpartid) {
//                             if (!json_is_string(jpartid)) {
//                                 is_valid = 0;
//                                 break;
//                             }
//                         }
//                     }
//                     else if (json_is_null(jpartids)) {
//                         /* JSON null means: no parts */
//                         continue;
//                     }
//                     if (!is_valid) break;
//                 }
//             }
//             else is_valid = json_is_null(jemailpartids);
//             if (!is_valid) {
//                 jmap_parser_invalid(&parser, "partIds");
//             }
//         }
//         else jmap_parser_invalid(&parser, key);
//         if (!json_object_size(jemailpartids)) {
//             jemailpartids = NULL;
//         }
//     }

//     /* Bail out for argument errors */
//     if (err) {
//         jmap_error(req, err);
//         json_decref(unsupported_filter);
//         goto done;
//     }
//     else if (json_array_size(parser.invalid)) {
//         jmap_error(req, json_pack("{s:s, s:O}", "type", "invalidArguments",
//                     "arguments", parser.invalid));
//         json_decref(unsupported_filter);
//         goto done;
//     }
//     /* Report unsupported filters */
//     if (json_array_size(unsupported_filter)) {
//         jmap_error(req, json_pack("{s:s, s:o}", "type", "unsupportedFilter",
//                     "filters", unsupported_filter));
//         goto done;
//     }
//     json_decref(unsupported_filter);

//     if (json_array_size(jmessageids) && _email_filter_contains_text(jfilter)) {
//         /* Render snippets */
//         r = _snippet_get(req, jfilter, jmessageids, jemailpartids, &snippets, &notfound);
//         if (r) goto done;
//     } else {
//         /* Trivial, snippets cant' match */
//         size_t i;
//         json_t *val;

//         snippets = json_pack("[]");
//         notfound = json_null();

//         json_array_foreach(jmessageids, i, val) {
//             json_array_append_new(snippets, json_pack("{s:s s:n s:n}",
//                         "emailId", json_string_value(val),
//                         "subject", "preview"));
//         }
//     }

//     /* Prepare response. */
//     json_t *res = json_pack("{s:o s:o}",
//                             "list", snippets, "notFound", notfound);
//     if (jfilter) json_object_set(res, "filter", jfilter);
//     jmap_ok(req, res);

// done:
//     jmap_email_contactfilter_fini(&contactfilter);
//     jmap_parser_fini(&parser);
//     buf_free(&buf);
//     return r;
// }

// static int _thread_is_shared_cb(const conv_guidrec_t *rec, void *rock)
// {
//     if (rec->part) return 0;
//     jmap_req_t *req = (jmap_req_t *)rock;
//     static int needrights = ACL_READ|ACL_LOOKUP;
//     if (jmap_hasrights_byname(req, rec->mboxname, needrights))
//         return IMAP_OK_COMPLETED;
//     return 0;
// }

// static int _thread_get(jmap_req_t *req, json_t *ids,
//                        json_t *list, json_t *not_found)
// {
//     conversation_t conv = CONVERSATION_INIT;
//     json_t *val;
//     size_t i;
//     int r = 0;

//     json_array_foreach(ids, i, val) {
//         conv_thread_t *thread;
//         char email_id[JMAP_EMAILID_SIZE];

//         const char *threadid = json_string_value(val);

//         memset(&conv, 0, sizeof(conversation_t));
//         r = conversation_load_advanced(req->cstate, _cid_from_id(threadid),
//                                        &conv, CONV_WITHTHREAD);
//         if (r || !conv.thread) {
//             json_array_append_new(not_found, json_string(threadid));
//             continue;
//         }

//         int is_own_account = !strcmp(req->userid, req->accountid);
//         json_t *ids = json_pack("[]");
//         for (thread = conv.thread; thread; thread = thread->next) {
//             if (!is_own_account) {
//                 const char *guidrep = message_guid_encode(&thread->guid);
//                 int r = conversations_guid_foreach(req->cstate, guidrep,
//                                                    _thread_is_shared_cb, req);
//                 if (r != IMAP_OK_COMPLETED) {
//                     if (r) {
//                         syslog(LOG_ERR, "jmap: _thread_is_shared_cb(%s): %s",
//                                 guidrep, error_message(r));
//                     }
//                     continue;
//                 }
//             }
//             jmap_set_emailid(&thread->guid, email_id);
//             json_array_append_new(ids, json_string(email_id));
//         }

//         /* if we didn't find any visible IDs, then the thread doesn't really
//            exist for this user */
//         if (!json_array_size(ids)) {
//             json_decref(ids);
//             json_array_append_new(not_found, json_string(threadid));
//             continue;
//         }

//         json_t *jthread = json_pack("{s:s s:o}", "id", threadid, "emailIds", ids);
//         json_array_append_new(list, jthread);

//         conversation_fini(&conv);
//     }

//     r = 0;

//     conversation_fini(&conv);
//     return r;
// }

// static const jmap_property_t thread_props[] = {
//     {
//         "id",
//         NULL,
//         JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
//     },
//     {
//         "emailIds",
//         NULL,
//         0
//     },
//     { NULL, NULL, 0 }
// };

// static int jmap_thread_get(jmap_req_t *req)
// {
//     struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
//     struct jmap_get get;
//     json_t *err = NULL;

//     /* Parse request */
//     jmap_get_parse(req, &parser, thread_props, /*allow_null_ids*/0,
//                    NULL, NULL, &get, &err);
//     if (err) {
//         jmap_error(req, err);
//         goto done;
//     }

//     /* Find threads */
//     int r = _thread_get(req, get.ids, get.list, get.not_found);
//     if (r) {
//         syslog(LOG_ERR, "jmap: Thread/get: %s", error_message(r));
//         jmap_error(req, jmap_server_error(r));
//         goto done;
//     }

//     json_t *jstate = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
//     get.state = xstrdup(json_string_value(jstate));
//     json_decref(jstate);
//     jmap_ok(req, jmap_get_reply(&get));

// done:
//     jmap_parser_fini(&parser);
//     jmap_get_fini(&get);
//     return 0;
// }

// struct email_getcontext {
//     struct seen *seendb;           /* Seen database for shared accounts */
//     hash_table seenseq_by_mbox_id; /* Cached seen sequences */
// };

// static void _email_getcontext_fini(struct email_getcontext *ctx)
// {
//     free_hash_table(&ctx->seenseq_by_mbox_id, (void(*)(void*))seqset_free);
//     seen_close(&ctx->seendb);
// }

struct email_getargs {
    /* Email/get arguments */
    hash_table *props; /* owned by JMAP get or process stack */
    hash_table *bodyprops;
    ptrarray_t want_headers;     /* array of header_prop */
    ptrarray_t want_bodyheaders; /* array of header_prop */
    short fetch_text_body;
    short fetch_html_body;
    short fetch_all_body;
    size_t max_body_bytes;
    /* Request-scoped context */
    // struct email_getcontext ctx;
};

#define _EMAIL_GET_ARGS_INITIALIZER \
    { \
        NULL, \
        NULL, \
        PTRARRAY_INITIALIZER, \
        PTRARRAY_INITIALIZER, \
        0, \
        0, \
        0, \
        0, \
    };
        // { \
        //     NULL, \
        //     HASH_TABLE_INITIALIZER \
        // } \

// /* Initialized in email_get_parse. *Not* thread-safe */
static hash_table _email_get_default_bodyprops = HASH_TABLE_INITIALIZER;
static hash_table _email_parse_default_props = HASH_TABLE_INITIALIZER;

static void _email_getargs_fini(struct email_getargs *args)
{
    if (args->bodyprops && args->bodyprops != &_email_get_default_bodyprops) {
        free_hash_table(args->bodyprops, NULL);
        free(args->bodyprops);
    }
    args->bodyprops = NULL;

    struct header_prop *prop;
    while ((prop = ptrarray_pop(&args->want_headers))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_headers);
    while ((prop = ptrarray_pop(&args->want_bodyheaders))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_bodyheaders);
    // _email_getcontext_fini(&args->ctx);
}

// /* A wrapper to aggregate JMAP keywords over a set of message records.
//  * Notably the $seen keyword is a pain to map from IMAP to JMAP:
//  * (1) it must only be reported if the IMAP \Seen flag is set on
//  *     all non-deleted index records.
//  * (2) it must be read from seen.db for shared mailboxes
//  */
// struct email_keywords {
//     const char *userid;
//     hash_table counts;
//     size_t totalmsgs;
//     hash_table *seenseq_by_mbox_id;
//     struct seen *seendb;
// };

// #define _EMAIL_KEYWORDS_INITIALIZER { NULL, HASH_TABLE_INITIALIZER, 0, NULL, NULL }

// /* Initialize the keyword aggregator for the authenticated userid.
//  *
//  * The seenseq hash table is used to read cached sequence sets
//  * read from seen.db per mailbox. If the hash table does not
//  * contain a sequence for the respective mailbox id, it is read
//  * from seen.db and stored in the map.
//  * Callers must free any entries in seenseq_by_mbox_id. */
// static void _email_keywords_init(struct email_keywords *keywords,
//                                  const char *userid,
//                                  struct seen *seendb,
//                                  hash_table *seenseq_by_mbox_id)
// {
//     construct_hash_table(&keywords->counts, 64, 0);
//     keywords->userid = userid;
//     keywords->seendb = seendb;
//     keywords->seenseq_by_mbox_id = seenseq_by_mbox_id;
// }

// static void _email_keywords_fini(struct email_keywords *keywords)
// {
//     free_hash_table(&keywords->counts, NULL);
// }

// static void _email_keywords_add_keyword(struct email_keywords *keywords,
//                                         const char *keyword)
// {
//     uintptr_t count = (uintptr_t) hash_lookup(keyword, &keywords->counts);
//     hash_insert(keyword, (void*) count+1, &keywords->counts);
// }

// static int _email_keywords_add_msgrecord(struct email_keywords *keywords,
//                                          msgrecord_t *mr)
// {
//     uint32_t uid, system_flags, internal_flags;
//     uint32_t user_flags[MAX_USER_FLAGS/32];
//     struct mailbox *mbox = NULL;

//     int r = msgrecord_get_uid(mr, &uid);
//     if (r) goto done;
//     r = msgrecord_get_mailbox(mr, &mbox);
//     if (r) goto done;
//     r = msgrecord_get_systemflags(mr, &system_flags);
//     if (r) goto done;
//     r = msgrecord_get_internalflags(mr, &internal_flags);
//     if (r) goto done;
//     if (system_flags & FLAG_DELETED || internal_flags & FLAG_INTERNAL_EXPUNGED) goto done;
//     r = msgrecord_get_userflags(mr, user_flags);
//     if (r) goto done;

//     int read_seendb = !mailbox_internal_seen(mbox, keywords->userid);

//     /* Read system flags */
//     if ((system_flags & FLAG_DRAFT))
//         _email_keywords_add_keyword(keywords, "$draft");
//     if ((system_flags & FLAG_FLAGGED))
//         _email_keywords_add_keyword(keywords, "$flagged");
//     if ((system_flags & FLAG_ANSWERED))
//         _email_keywords_add_keyword(keywords, "$answered");
//     if (!read_seendb && system_flags & FLAG_SEEN)
//         _email_keywords_add_keyword(keywords, "$seen");

//     /* Read user flags */
//     struct buf buf = BUF_INITIALIZER;
//     int i;
//     for (i = 0 ; i < MAX_USER_FLAGS ; i++) {
//         if (mbox->flagname[i] && (user_flags[i/32] & 1<<(i&31))) {
//             buf_setcstr(&buf, mbox->flagname[i]);
//             _email_keywords_add_keyword(keywords, buf_lcase(&buf));
//         }
//     }
//     buf_free(&buf);

//     if (read_seendb) {
//         /* Read $seen keyword from seen.db for shared accounts */
//         struct seqset *seenseq = hash_lookup(mbox->uniqueid, keywords->seenseq_by_mbox_id);
//         if (!seenseq) {
//             struct seendata sd = SEENDATA_INITIALIZER;
//             int r = seen_read(keywords->seendb, mbox->uniqueid, &sd);
//             if (!r) {
//                 seenseq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
//                 hash_insert(mbox->uniqueid, seenseq, keywords->seenseq_by_mbox_id);
//                 seen_freedata(&sd);
//             }
//             else {
//                 syslog(LOG_ERR, "Could not read seen state for %s (%s)",
//                         keywords->userid, error_message(r));
//             }
//         }

//         if (seenseq && seqset_ismember(seenseq, uid))
//             _email_keywords_add_keyword(keywords, "$seen");
//     }

//     /* Count message */
//     keywords->totalmsgs++;

// done:
//     return r;
// }

// static json_t *_email_keywords_to_jmap(struct email_keywords *keywords)
// {
//     json_t *jkeywords = json_object();
//     hash_iter *kwiter = hash_table_iter(&keywords->counts);
//     while (hash_iter_next(kwiter)) {
//         const char *keyword = hash_iter_key(kwiter);
//         uintptr_t count = (uintptr_t) hash_iter_val(kwiter);
//         if (strcasecmp(keyword, "$seen") || count == keywords->totalmsgs) {
//             json_object_set_new(jkeywords, keyword, json_true());
//         }
//     }
//     hash_iter_free(&kwiter);
//     return jkeywords;
// }


// struct email_get_keywords_rock {
//     jmap_req_t *req;
//     struct email_keywords keywords;
// };

// static int _email_get_keywords_cb(const conv_guidrec_t *rec, void *vrock)
// {
//     struct email_get_keywords_rock *rock = vrock;
//     jmap_req_t *req = rock->req;
//     struct mailbox *mbox = NULL;
//     msgrecord_t *mr = NULL;

//     if (rec->part) return 0;

//     if (!jmap_hasrights_byname(req, rec->mboxname, ACL_READ|ACL_LOOKUP)) return 0;

//     /* Fetch system flags */
//     int r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
//     if (r) return r;

//     r = msgrecord_find(mbox, rec->uid, &mr);
//     if (r) goto done;

//     r = _email_keywords_add_msgrecord(&rock->keywords, mr);

// done:
//     msgrecord_unref(&mr);
//     jmap_closembox(req, &mbox);
//     return r;
// }

// static int _email_get_keywords(jmap_req_t *req,
//                                struct email_getcontext *ctx,
//                                const char *msgid,
//                                json_t **jkeywords)
// {
//     /* Initialize seen.db and sequence set cache */
//     if (ctx->seendb == NULL && strcmp(req->accountid, req->userid)) {
//         int r = seen_open(req->userid, SEEN_CREATE, &ctx->seendb);
//         if (r) return r;
//     }
//     if (ctx->seenseq_by_mbox_id.size == 0) {
//         construct_hash_table(&ctx->seenseq_by_mbox_id, 128, 0);
//     }
//     /* Gather keywords for all message records */
//     struct email_get_keywords_rock rock = { req, _EMAIL_KEYWORDS_INITIALIZER };
//     _email_keywords_init(&rock.keywords, req->userid, ctx->seendb, &ctx->seenseq_by_mbox_id);
//     int r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
//                                        _email_get_keywords_cb, &rock);
//     *jkeywords = _email_keywords_to_jmap(&rock.keywords);
//     _email_keywords_fini(&rock.keywords);
//     return r;
// }

// struct email_get_snoozed_rock {
//     jmap_req_t *req;
//     json_t *snoozed;
// };

// static int _email_get_snoozed_cb(const conv_guidrec_t *rec, void *vrock)
// {
//     struct email_get_snoozed_rock *rock = vrock;

//     if (rec->part) return 0;

//     if (!jmap_hasrights_byname(rock->req, rec->mboxname, ACL_READ|ACL_LOOKUP))
//         return 0;

//     if (FLAG_INTERNAL_SNOOZED ==
//         (rec->internal_flags & (FLAG_INTERNAL_SNOOZED|FLAG_INTERNAL_EXPUNGED))) {
//         /* Fetch snoozed annotation */
//         rock->snoozed = jmap_fetch_snoozed(rec->mboxname, rec->uid);
//     }

//     /* Short-circuit the foreach if we find a snoozed message */
//     return (rock->snoozed != NULL);
// }

// static void _email_parse_wantheaders(json_t *jprops,
//                                      struct jmap_parser *parser,
//                                      const char *prop_name,
//                                      ptrarray_t *want_headers)
// {
//     size_t i;
//     json_t *jval;
//     json_array_foreach(jprops, i, jval) {
//         const char *s = json_string_value(jval);
//         if (!s || strncmp(s, "header:", 7))
//             continue;
//         struct header_prop *hprop;
//         if ((hprop = _header_parseprop(s))) {
//             ptrarray_append(want_headers, hprop);
//         }
//         else {
//             jmap_parser_push_index(parser, prop_name, i, s);
//             jmap_parser_invalid(parser, NULL);
//             jmap_parser_pop(parser);
//         }
//     }
// }

static void _email_init_default_props(hash_table *props)
{
    /* Initialize process-owned default property list */
    construct_hash_table(props, 32, 0);
    if (props == &_email_get_default_bodyprops) {
        // [ "partId", "blobId", "size", "name", "type", "charset",
            // "disposition", "cid", "language", "location" ]
        hash_insert("partId",      (void*)1, props);
        hash_insert("blobId",      (void*)1, props);
        hash_insert("size",        (void*)1, props);
        hash_insert("name",        (void*)1, props);
        hash_insert("type",        (void*)1, props);
        hash_insert("charset",     (void*)1, props);

        hash_insert("disposition", (void*)1, props);
        hash_insert("cid",         (void*)1, props);
        hash_insert("language",    (void*)1, props);
        hash_insert("location",    (void*)1, props);
    }
    else {
        // [ "id", "blobId", "threadId", "mailboxIds", "keywords", "size",
        // "receivedAt", "messageId", "inReplyTo", "references", "sender", "from",
        // "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment",
        // "preview", "bodyValues", "textBody", "htmlBody", "attachments" ]

        hash_insert("blobId",        (void*)1, props);
        hash_insert("threadId",      (void*)1, props);
        hash_insert("mailboxIds",    (void*)1, props);
        hash_insert("keywords",      (void*)1, props);
        hash_insert("size",          (void*)1, props);

        hash_insert("receivedAt",    (void*)1, props);
        hash_insert("messageId",     (void*)1, props);
        hash_insert("inReplyTo",     (void*)1, props);
        hash_insert("references",    (void*)1, props);
        hash_insert("sender",        (void*)1, props);
        hash_insert("from",          (void*)1, props);

        hash_insert("to",            (void*)1, props);
        hash_insert("cc",            (void*)1, props);
        hash_insert("bcc",           (void*)1, props);
        hash_insert("replyTo",       (void*)1, props);
        hash_insert("subject",       (void*)1, props);
        hash_insert("sentAt",        (void*)1, props);
        hash_insert("hasAttachment", (void*)1, props);

        hash_insert("preview",       (void*)1, props);
        hash_insert("bodyValues",    (void*)1, props);
        hash_insert("textBody",      (void*)1, props);
        hash_insert("htmlBody",      (void*)1, props);
        hash_insert("attachments",   (void*)1, props);
    }
}

// static int _email_getargs_parse(jmap_req_t *req __attribute__((unused)),
//                                 struct jmap_parser *parser,
//                                 const char *key,
//                                 json_t *arg,
//                                 void *rock)
// {
//     struct email_getargs *args = (struct email_getargs *) rock;
//     int r = 1;

//     /* bodyProperties */
//     if (!strcmp(key, "bodyProperties")) {
//         if (jmap_parse_strings(arg, parser, "bodyProperties")) {
//             size_t i;
//             json_t *val;

//             args->bodyprops = xzmalloc(sizeof(hash_table));
//             construct_hash_table(args->bodyprops, json_array_size(arg) + 1, 0);
//             json_array_foreach(arg, i, val) {
//                 hash_insert(json_string_value(val), (void*)1, args->bodyprops);
//             }
//         }
//         /* header:Xxx properties */
//         _email_parse_wantheaders(arg, parser, "bodyProperties",
//                                  &args->want_bodyheaders);
//     }

//     /* fetchTextBodyValues */
//     else if (!strcmp(key, "fetchTextBodyValues") && json_is_boolean(arg)) {
//         args->fetch_text_body = json_boolean_value(arg);
//     }

//     /* fetchHTMLBodyValues */
//     else if (!strcmp(key, "fetchHTMLBodyValues") && json_is_boolean(arg)) {
//         args->fetch_html_body = json_boolean_value(arg);
//     }

//     /* fetchAllBodyValues */
//     else if (!strcmp(key, "fetchAllBodyValues") && json_is_boolean(arg)) {
//         args->fetch_all_body = json_boolean_value(arg);
//     }

//     /* maxBodyValueBytes */
//     else if (!strcmp(key, "maxBodyValueBytes") &&
//              json_is_integer(arg) && json_integer_value(arg) > 0) {
//         args->max_body_bytes = json_integer_value(arg);
//     }

//     else r = 0;

//     return r;
// }

struct cyrusmsg {
    msgrecord_t *mr;                 /* Message record for top-level message */
    const struct body *part0;        /* Root body-part */
    const struct body *rfc822part;   /* RFC822 root part for embedded message */
    const struct buf *mime;          /* Raw MIME buffer */
    // json_t *imagesize_by_part;       /* FastMail-specific extension */

    // message_t *_m;                   /* Message loaded from message record */
    struct body *_mybody;            /* Bodystructure */
    struct buf _mymime;              /* Raw MIME buffer */
    struct headers *_headers;        /* Parsed part0 headers. Don't free. */
    hash_table *_headers_by_part_id; /* Parsed subpart headers. Don't free. */
    ptrarray_t _headers_mempool;     /* Allocated headers memory */
};

static void _cyrusmsg_free(struct cyrusmsg **msgptr)
{
    if (msgptr == NULL || *msgptr == NULL) return;

    struct cyrusmsg *msg = *msgptr;
    if (msg->_mybody) {
        message_free_body(msg->_mybody);
        free(msg->_mybody);
    }
    buf_free(&msg->_mymime);
    // json_decref(msg->imagesize_by_part);
    if (msg->_headers_by_part_id) {
        free_hash_table(msg->_headers_by_part_id, NULL);
        free(msg->_headers_by_part_id);
    }
    struct headers *hdrs;
    while ((hdrs = ptrarray_pop(&msg->_headers_mempool))) {
        _headers_fini(hdrs);
        free(hdrs);
    }
    ptrarray_fini(&msg->_headers_mempool);
    free(*msgptr);
    *msgptr = NULL;
}

// static int _cyrusmsg_from_record(msgrecord_t *mr, struct cyrusmsg **msgptr)
// {
//     struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
//     msg->mr = mr;
//     *msgptr = msg;
//     return 0;
// }

// static int _cyrusmsg_from_bodypart(msgrecord_t *mr,
//                                    struct body *body,
//                                    const struct body *part,
//                                    struct cyrusmsg **msgptr)
// {
//     struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
//     msg->mr = mr;
//     msg->part0 = body;
//     msg->rfc822part = part;
//     *msgptr = msg;
//     return 0;
// }

static void _cyrusmsg_init_partids(struct body *body, const char *part_id)
{
    if (!body) return;

    if (!strcmp(body->type, "MULTIPART")) {
        struct buf buf = BUF_INITIALIZER;
        int i;
        for (i = 0; i < body->numparts; i++) {
            struct body *subpart = body->subpart + i;
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", i + 1);
            subpart->part_id = buf_release(&buf);
            _cyrusmsg_init_partids(subpart, subpart->part_id);
        }
        free(body->part_id);
        body->part_id = NULL;
        buf_free(&buf);
    }
    else {
        struct buf buf = BUF_INITIALIZER;
        if (!body->part_id) {
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", 1);
            body->part_id = buf_release(&buf);
        }
        buf_free(&buf);

        if (!strcmp(body->type, "MESSAGE") &&
            !strcmp(body->subtype, "RFC822")) {
            _cyrusmsg_init_partids(body->subpart, body->part_id);
        }
    }
}


static int _cyrusmsg_from_buf(const struct buf *buf, struct cyrusmsg **msgptr)
{
    /* No more return from here */
    struct body *mybody = xzmalloc(sizeof(struct body));
    struct protstream *pr = prot_readmap(buf_base(buf), buf_len(buf));

    /* Pre-run compliance check */
    int r = message_copy_strict(pr, /*to*/NULL, buf_len(buf), /*allow_null*/0);
    if (r) goto done;

    /* Parse message */
    /*int*/ r = message_parse_mapped(buf_base(buf), buf_len(buf), mybody);
    if (r || !mybody->subpart) {
        r = IMAP_MESSAGE_BADHEADER;
        goto done;
    }

    /* parse_mapped doesn't set part ids */
    _cyrusmsg_init_partids(mybody->subpart, NULL);

    struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
    msg->_mybody = mybody;
    msg->part0 = mybody->subpart;
    msg->rfc822part = mybody;
    msg->mime = buf;
    *msgptr = msg;

done:
    if (pr) prot_free(pr);
    if (r && mybody) {
        message_free_body(mybody);
        free(mybody);
    }
    return r;
}

static int _cyrusmsg_need_part0(struct cyrusmsg *msg)
{
    if (msg->part0)
        return 0;
    if (!msg->mr)
        return IMAP_INTERNAL;

    assert(msg->part0); // EDITED
    // int r = msgrecord_extract_bodystructure(msg->mr, &msg->_mybody);
    // if (r) return r;
    // msg->part0 = msg->_mybody;
    return 0;
}

static int _cyrusmsg_need_mime(struct cyrusmsg *msg)
{
    if (msg->mime) return 0;
    if (msg->mr == NULL) {
        return IMAP_INTERNAL;
    }
    assert(msg->mime); // EDITED
    // int r = msgrecord_get_body(msg->mr, &msg->_mymime);
    // msg->mime = &msg->_mymime;
    // if (r) return r;
    return 0;
}

static int _cyrusmsg_get_headers(struct cyrusmsg *msg,
                                 const struct body *part,
                                 struct headers **headersptr)
{

    if (part == NULL && msg->_headers) {
        *headersptr = msg->_headers;
        return 0;
    }
    else if (part && part->part_id) {
        if (msg->_headers_by_part_id) {
            *headersptr = hash_lookup(part->part_id, msg->_headers_by_part_id);
            if (*headersptr) return 0;
        }
        else {
            msg->_headers_by_part_id = xzmalloc(sizeof(hash_table));
            construct_hash_table(msg->_headers_by_part_id, 64, 0);
        }
    }

    /* Prefetch body structure */
    int r = _cyrusmsg_need_part0(msg);
    if (r) return r;
    /* Prefetch MIME message */
    assert(msg->mime);
    // r = _cyrusmsg_need_mime(msg); // EDITED
    // if (r) return r;
    const struct body *header_part = part ? part : msg->part0;
    struct headers *headers = xmalloc(sizeof(struct headers));
    _headers_init(headers);
    _headers_from_mime(msg->mime->s + header_part->header_offset,
                       header_part->header_size, headers);
    if (part && part->part_id)
        hash_insert(part->part_id, headers, msg->_headers_by_part_id);
    else if (part == NULL)
        msg->_headers = headers;
    ptrarray_append(&msg->_headers_mempool, headers);
    *headersptr = headers;
    return 0;
}

static json_t * _email_get_header(struct cyrusmsg *msg,
                                  const struct body *part,
                                  const char *lcasename,
                                  enum _header_form want_form,
                                  int want_all)
{
    if (!part) {
        /* Fetch bodypart */
        int r = _cyrusmsg_need_part0(msg);
        if (r) return json_null();
        // part = msg->part0;
        part = msg->part0->subpart;
    }

    /* Try to read the header from the parsed body part */
    if (part && !want_all && want_form != HEADER_FORM_RAW) {
        json_t *jval = NULL;
        if (!strcmp("messageId", lcasename)) {
            jval = want_form == HEADER_FORM_MESSAGEIDS ?
                _header_as_messageids(part->message_id) : json_null();
        }
        else if (!strcmp("inReplyTo", lcasename)) {
            jval = want_form == HEADER_FORM_MESSAGEIDS ?
                _header_as_messageids(part->in_reply_to) : json_null();
        }
        else if (!strcmp("subject", lcasename)) {
            jval = want_form == HEADER_FORM_TEXT ?
                _header_as_text(part->subject) : json_null();
        }
        else if (!strcmp("from", lcasename)) {
            jval = want_form == HEADER_FORM_ADDRESSES ?
                _emailaddresses_from_addr(part->from) : json_null();
        }
        else if (!strcmp("to", lcasename)) {
            jval = want_form == HEADER_FORM_ADDRESSES ?
                _emailaddresses_from_addr(part->to) : json_null();
        }
        else if (!strcmp("cc", lcasename)) {
            jval = want_form == HEADER_FORM_ADDRESSES ?
                _emailaddresses_from_addr(part->cc) : json_null();
        }
        else if (!strcmp("bcc", lcasename)) {
            jval = want_form == HEADER_FORM_ADDRESSES ?
                _emailaddresses_from_addr(part->bcc) : json_null();
        }
        // else if (!strcmp("sender", lcasename)) {
        //     jval = want_form == HEADER_FORM_ADDRESSES ?
        //         _emailaddresses_from_addr(part->sender) : json_null();
        // }
        else if (!strcmp("sentAt", lcasename)) {
            jval = json_null();
            if (want_form == HEADER_FORM_DATE) {
                struct offsettime t;
                if (offsettime_from_rfc5322(part->date, &t, DATETIME_FULL) != -1) {
                    char datestr[30];
                    offsettime_to_iso8601(&t, datestr, 30, 1);
                    jval = json_string(datestr);
                }
            }
        }
        if (jval) return jval;
    }

    /* Determine header form converter */
    json_t* (*conv)(const char *raw);
    switch (want_form) {
        case HEADER_FORM_TEXT:
            conv = _header_as_text;
            break;
        case HEADER_FORM_DATE:
            conv = _header_as_date;
            break;
        case HEADER_FORM_ADDRESSES:
            conv = _header_as_addresses;
            break;
        case HEADER_FORM_MESSAGEIDS:
            conv = _header_as_messageids;
            break;
        case HEADER_FORM_URLS:
            conv = _header_as_urls;
            break;
        default:
            conv = _header_as_raw;
    }

    /* Try to read the value from the index record or header cache */
    // EDITED
    // if (msg->mr && part == msg->part0 && !want_all && want_form != HEADER_FORM_RAW) {
    //     if (!msg->_m) {
    //         int r = msgrecord_get_message(msg->mr, &msg->_m);
    //         if (r) return json_null();
    //     }
    //     struct buf buf = BUF_INITIALIZER;
    //     int r = message_get_field(msg->_m, lcasename, MESSAGE_RAW|MESSAGE_LAST, &buf);
    //     if (r) return json_null();
    //     json_t *jval = NULL;
    //     if (buf_len(&buf)) jval = conv(buf_cstring(&buf));
    //     buf_free(&buf);
    //     if (jval) return jval;
    // }

    /* Read the raw MIME headers */
    struct headers *partheaders = NULL;
    int r = _cyrusmsg_get_headers(msg, part, &partheaders);
    if (r) return json_null();

    /* Lookup array of EmailHeader objects by name */
    json_t *jheaders = json_object_get(partheaders->all, lcasename);
    if (!jheaders || !json_array_size(jheaders)) {
        return want_all ? json_array() : json_null();
    }

    /* Convert header values */
    if (want_all) {
        json_t *allvals = json_array();
        size_t i;
        for (i = 0; i < json_array_size(jheaders); i++) {
            json_t *jheader = json_array_get(jheaders, i);
            json_t *jheaderval = json_object_get(jheader, "value");
            json_array_append_new(allvals, conv(json_string_value(jheaderval)));
        }
        return allvals;
    }

    json_t *jheader = json_array_get(jheaders, json_array_size(jheaders) - 1);
    json_t *jheaderval = json_object_get(jheader, "value");
    return conv(json_string_value(jheaderval));
}

static int _email_get_meta(jmap_req_t *req,
                           struct email_getargs *args,
                           struct cyrusmsg *msg,
                           json_t *email)
{
    int r = 0;
    hash_table *props = args->props;
    char email_id[JMAP_EMAILID_SIZE];

    if (msg->rfc822part) {
        if (jmap_wantprop(props, "id")) {
            json_object_set_new(email, "id", json_null());
        }
        if (jmap_wantprop(props, "blobId")) {
            char blob_id[JMAP_BLOBID_SIZE];
            jmap_set_blobid(&msg->rfc822part->content_guid, blob_id);
            json_object_set_new(email, "blobId", json_string(blob_id));
        }
        // if (jmap_wantprop(props, "threadId"))
        //     json_object_set_new(email, "threadId", json_null());
        // if (jmap_wantprop(props, "mailboxIds"))
        //     json_object_set_new(email, "mailboxIds", json_null());
        // if (jmap_wantprop(props, "keywords"))
        //     json_object_set_new(email, "keywords", json_object());
        if (jmap_wantprop(props, "size")) {
            size_t size = msg->rfc822part->subpart->header_size + msg->rfc822part->subpart->content_size;
            json_object_set_new(email, "size", json_integer(size));
        }
        if (jmap_wantprop(props, "receivedAt"))
            json_object_set_new(email, "receivedAt", json_null());
        return 0;
    }

    /* This is a top-level messages with a regular index record. */

    /* Determine message id */
    struct message_guid guid;
    guid = msg->part0->guid; // EDITED
    // r = msgrecord_get_guid(msg->mr, &guid);
    // if (r) goto done;

    jmap_set_emailid(&guid, email_id);

    /* id */
    if (jmap_wantprop(props, "id")) {
        json_object_set_new(email, "id", json_string(email_id));
    }

    /* blobId */
    if (jmap_wantprop(props, "blobId")) {
        char blob_id[JMAP_BLOBID_SIZE];
        jmap_set_blobid(&guid, blob_id);
        json_object_set_new(email, "blobId", json_string(blob_id));
    }

    /* threadid */
    // if (jmap_wantprop(props, "threadId")) {
    //     bit64 cid;
    //     r = msgrecord_get_cid(msg->mr, &cid);
    //     if (r) goto done;
    //     char thread_id[JMAP_THREADID_SIZE];
    //     jmap_set_threadid(cid, thread_id);
    //     json_object_set_new(email, "threadId", json_string(thread_id));
    // }

    /* mailboxIds */
    // if (jmap_wantprop(props, "mailboxIds") ||
    //     jmap_wantprop(props, "addedDates") || jmap_wantprop(props, "removedDates")) {
    //     json_t *mboxids =
    //         jmap_wantprop(props, "mailboxIds") ? json_object() : NULL;
    //     json_t *added =
    //         jmap_wantprop(props, "addedDates") ? json_object() : NULL;
    //     json_t *removed =
    //         jmap_wantprop(props, "removedDates") ? json_object() : NULL;
    //     json_t *mailboxes = _email_mailboxes(req, email_id);

    //     json_t *val;
    //     const char *mboxid;
    //     json_object_foreach(mailboxes, mboxid, val) {
    //         json_t *exists = json_object_get(val, "added");

    //         if (exists) {
    //             if (mboxids) json_object_set_new(mboxids, mboxid, json_true());
    //             if (added) json_object_set(added, mboxid, exists);
    //         }
    //         else if (removed) {
    //             json_object_set(removed, mboxid, json_object_get(val, "removed"));
    //         }
    //     }
    //     json_decref(mailboxes);
    //     if (mboxids) json_object_set_new(email, "mailboxIds", mboxids);
    //     if (removed) json_object_set_new(email, "removedDates", removed);
    //     if (added) json_object_set_new(email, "addedDates", added);
    // }

    /* keywords */
    // if (jmap_wantprop(props, "keywords")) {
    //     json_t *keywords = NULL;
    //     r = _email_get_keywords(req, &args->ctx, email_id, &keywords);
    //     if (r) goto done;
    //     json_object_set_new(email, "keywords", keywords);
    // }

    /* size */
    // Handled above.
    // if (jmap_wantprop(props, "size")) {
    //     uint32_t size = UINT32_MAX; // FIXME EDITED - should be able to pull the size back out of the buf.

    //     // r = msgrecord_get_size(msg->mr, &size);
    //     // if (r) goto done;
    //     json_object_set_new(email, "size", json_integer(size));
    // }

    /* receivedAt */
    if (jmap_wantprop(props, "receivedAt")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t = 0;
        // EDITED FIXME
        // r = msgrecord_get_internaldate(msg->mr, &t);
        // if (r) goto done;
        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(email, "receivedAt", json_string(datestr));
    }

    /* FastMail-extension properties */
    // if (jmap_wantprop(props, "trustedSender")) {
    //     json_t *trusted_sender = NULL;
    //     int has_trusted_flag = 0;
    //     r = msgrecord_hasflag(msg->mr, "$IsTrusted", &has_trusted_flag);
    //     if (r) goto done;
    //     if (has_trusted_flag) {
    //         struct buf buf = BUF_INITIALIZER;
    //         _email_read_annot(req, msg->mr, "/vendor/messagingengine.com/trusted", &buf);
    //         if (buf_len(&buf)) {
    //             trusted_sender = json_string(buf_cstring(&buf));
    //         }
    //         buf_free(&buf);
    //     }
    //     json_object_set_new(email, "trustedSender", trusted_sender ?
    //             trusted_sender : json_null());
    // }

    // if (jmap_wantprop(props, "spamScore")) {
    //     int r = 0;
    //     struct buf buf = BUF_INITIALIZER;
    //     json_t *jval = json_null();
    //     if (!msg->_m) r = msgrecord_get_message(msg->mr, &msg->_m);
    //     if (!r) r = message_get_field(msg->_m, "x-spam-score", MESSAGE_RAW, &buf);
    //     if (!r && buf_len(&buf)) jval = json_real(atof(buf_cstring(&buf)));
    //     json_object_set_new(email, "spamScore", jval);
    //     buf_free(&buf);
    // }

    // if (jmap_wantprop(props, "snoozed")) {
    //     struct email_get_snoozed_rock rock = { req, NULL };

    //     /* Look for the first snoozed copy of this email_id */
    //     conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
    //                                _email_get_snoozed_cb, &rock);

    //     json_object_set_new(email, "snoozed",
    //                         rock.snoozed ? rock.snoozed : json_null());
    // }

done:
    return r;
}

static int _email_get_headers(jmap_req_t *req __attribute__((unused)),
                              struct email_getargs *args,
                              struct cyrusmsg *msg,
                              json_t *email)
{
    int r = 0;
    hash_table *props = args->props;

    if (jmap_wantprop(props, "headers") || args->want_headers.count) {
        /* headers */
        if (jmap_wantprop(props, "headers")) {
            struct headers *headers = NULL;
            r = _cyrusmsg_get_headers(msg, NULL, &headers);
            if (r) return r;
            json_object_set(email, "headers", headers->raw); /* incref! */
        }
        /* headers:Xxx */
        if (ptrarray_size(&args->want_headers)) {
            int i;
            for (i = 0; i < ptrarray_size(&args->want_headers); i++) {
                struct header_prop *want_header = ptrarray_nth(&args->want_headers, i);
                json_t *jheader = _email_get_header(msg, NULL, want_header->lcasename,
                                      want_header->form, want_header->all);
                json_object_set_new(email, want_header->prop, jheader);
            }
        }
    }

    /* references */
    if (jmap_wantprop(props, "references")) {
        json_t *references = _email_get_header(msg, NULL, "references",
                                               HEADER_FORM_MESSAGEIDS,/*all*/0);
        json_object_set_new(email, "references", references);
    }

    /* The following fields are all read from the body-part structure */
    const struct body *part = NULL;
    if (jmap_wantprop(props, "messageId") ||
        jmap_wantprop(props, "inReplyTo") ||
        jmap_wantprop(props, "from") ||
        jmap_wantprop(props, "to") ||
        jmap_wantprop(props, "cc") ||
        jmap_wantprop(props, "bcc") ||
        jmap_wantprop(props, "subject") ||
        jmap_wantprop(props, "sender") ||
        jmap_wantprop(props, "replyTo") ||
        jmap_wantprop(props, "sentAt")) {
        if (msg->rfc822part) {
            part = msg->rfc822part->subpart;
        }
        else {
            r = _cyrusmsg_need_part0(msg);
            if (r) return r;
            part = msg->part0;
        }
    }
    /* messageId */
    if (jmap_wantprop(props, "messageId")) {
        json_object_set_new(email, "messageId",
                _header_as_messageids(part->message_id));
    }
    /* inReplyTo */
    if (jmap_wantprop(props, "inReplyTo")) {
        json_object_set_new(email, "inReplyTo",
                _header_as_messageids(part->in_reply_to));
    }
    /* from */
    if (jmap_wantprop(props, "from")) {
        json_object_set_new(email, "from",
                _emailaddresses_from_addr(part->from));
    }
    /* to */
    if (jmap_wantprop(props, "to")) {
        json_object_set_new(email, "to",
                _emailaddresses_from_addr(part->to));
    }
    /* cc */
    if (jmap_wantprop(props, "cc")) {
        json_object_set_new(email, "cc",
                _emailaddresses_from_addr(part->cc));
    }
    /* bcc */
    if (jmap_wantprop(props, "bcc")) {
        json_object_set_new(email, "bcc",
                _emailaddresses_from_addr(part->bcc));
    }
    /* subject */
    if (jmap_wantprop(props, "subject")) {
        json_object_set_new(email, "subject",
                _header_as_text(part->subject));
    }
    // /* sender */
    if (jmap_wantprop(props, "sender")) {
        json_object_set_new(email, "sender",
                _emailaddresses_from_addr(part->sender));
    }
    // if (jmap_wantprop(props, "sender")) {
    //     json_t *sender = _email_get_header(msg, NULL, "sender",
    //                                        HEADER_FORM_ADDRESSES,/*all*/0);
    //     json_object_set_new(email, "sender", sender);
    // }
    // /* replyTo */
    if (jmap_wantprop(props, "replyTo")) {
        json_object_set_new(email, "replyTo",
                _emailaddresses_from_addr(part->reply_to));
    }
    // if (jmap_wantprop(props, "replyTo")) {
    //     json_t *replyTo = _email_get_header(msg, NULL, "reply-to",
    //                                         HEADER_FORM_ADDRESSES, /*all*/0);
    //     json_object_set_new(email, "replyTo", replyTo);
    // }


    /* sentAt */
    if (jmap_wantprop(props, "sentAt")) {
        json_t *jsent_at = json_null();
        struct offsettime t;
        if (offsettime_from_rfc5322(part->date, &t, DATETIME_FULL) != -1) {
            char datestr[30];
            offsettime_to_iso8601(&t, datestr, 30, 1);
            jsent_at = json_string(datestr);
        }
        json_object_set_new(email, "sentAt", jsent_at);
    }

    return r;
}

static json_t *_email_get_bodypart(jmap_req_t *req,
                                   struct email_getargs *args,
                                   struct cyrusmsg *msg,
                                   const struct body *part)
{
    struct buf buf = BUF_INITIALIZER;
    struct param *param;

    hash_table *bodyprops = args->bodyprops;
    ptrarray_t *want_bodyheaders = &args->want_bodyheaders;

    json_t *jbodypart = json_object();

    /* partId */
    if (jmap_wantprop(bodyprops, "partId")) {
        json_t *jpart_id = json_null();
        if (strcasecmp(part->type, "MULTIPART"))
            jpart_id = json_string(part->part_id);
        json_object_set_new(jbodypart, "partId", jpart_id);
    }

    /* blobId */
    if (jmap_wantprop(bodyprops, "blobId")) {
        json_t *jblob_id = json_null();
        if (!message_guid_isnull(&part->content_guid)) {
            char blob_id[JMAP_BLOBID_SIZE];
            jmap_set_blobid(&part->content_guid, blob_id);
            jblob_id = json_string(blob_id);
        }
        json_object_set_new(jbodypart, "blobId", jblob_id);
    }

    /* size */
    if (jmap_wantprop(bodyprops, "size")) {
        size_t size = 0;
        if (part->numparts && strcasecmp(part->type, "MESSAGE")) {
            /* Multipart */
            size = 0;
        }
        else if (part->charset_enc & 0xff) {
            if (part->decoded_content_size == 0) {
                char *tmp = NULL;
                size_t tmp_size;
                int r = _cyrusmsg_need_mime(msg);
                if (!r)  {
                    charset_decode_mimebody(msg->mime->s + part->content_offset,
                            part->content_size, part->charset_enc, &tmp, &tmp_size);
                    size = tmp_size;
                    free(tmp);
                }
            }
            else {
                size = part->decoded_content_size;
            }
        }
        else {
            size = part->content_size;
        }
        json_object_set_new(jbodypart, "size", json_integer(size));
    }

    /* headers */
    if (jmap_wantprop(bodyprops, "headers") || want_bodyheaders->count) {
        /* headers */
        if (jmap_wantprop(bodyprops, "headers")) {
            struct headers *headers = NULL;
            int r = _cyrusmsg_get_headers(msg, part, &headers);
            if (!r) {
                json_object_set(jbodypart, "headers", headers->raw); /* incref! */
            }
            else {
                json_object_set(jbodypart, "headers", json_null());
            }
        }
        /* headers:Xxx */
        if (ptrarray_size(want_bodyheaders)) {
            int i;
            for (i = 0; i < ptrarray_size(want_bodyheaders); i++) {
                struct header_prop *want_header = ptrarray_nth(want_bodyheaders, i);
                json_t *jheader = _email_get_header(msg, part, want_header->lcasename,
                                                    want_header->form, want_header->all);
                json_object_set_new(jbodypart, want_header->prop, jheader);
            }
        }
    }

    /* name */
    if (jmap_wantprop(bodyprops, "name")) {
        const char *fname = NULL;
        char *val = NULL;
        int is_extended = 0;

        /* Lookup name parameter. Disposition header has precedence */
        for (param = part->disposition_params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "filename", 8)) {
                is_extended = param->attribute[8] == '*';
                fname = param->value;
                break;
            }
        }
        /* Lookup Content-Type parameters */
        if (!fname) {
            for (param = part->params; param; param = param->next) {
                if (!strncasecmp(param->attribute, "name", 4)) {
                    is_extended = param->attribute[4] == '*';
                    fname = param->value;
                    break;
                }
            }
        }

        /* Decode header value */
        if (fname && is_extended) {
            val = charset_parse_mimexvalue(fname, NULL);
        }
        if (fname && !val) {
            val = charset_parse_mimeheader(fname, CHARSET_KEEPCASE|CHARSET_MIME_UTF8);
        }
        json_object_set_new(jbodypart, "name", val ?
                json_string(val) : json_null());
        free(val);
    }

    /* type */
    if (jmap_wantprop(bodyprops, "type")) {
        buf_setcstr(&buf, part->type);
        if (part->subtype) {
            buf_appendcstr(&buf, "/");
            buf_appendcstr(&buf, part->subtype);
        }
        json_object_set_new(jbodypart, "type", json_string(buf_lcase(&buf)));
    }

    /* charset */
    if (jmap_wantprop(bodyprops, "charset")) {
        const char *charset_id = NULL;
        if (part->charset_id) {
            charset_id = part->charset_id;
        }
        else if (!strcasecmp(part->type, "TEXT")) {
            charset_id = "us-ascii";
        }
        json_object_set_new(jbodypart, "charset", charset_id ?
                json_string(charset_id) : json_null());
    }

    /* disposition */
    if (jmap_wantprop(bodyprops, "disposition")) {
        json_t *jdisp = json_null();
        if (part->disposition) {
            char *disp = lcase(xstrdup(part->disposition));
            jdisp = json_string(disp);
            free(disp);
        }
        json_object_set_new(jbodypart, "disposition", jdisp);
    }


    /* cid */
    if (jmap_wantprop(bodyprops, "cid")) {
        json_t *jcid = _email_get_header(msg, part, "content-id",
                                         HEADER_FORM_MESSAGEIDS, /*all*/0);
        json_object_set(jbodypart, "cid", json_array_size(jcid) ?
                json_array_get(jcid, 0) : json_null());
        json_decref(jcid);
    }


    /* language */
    if (jmap_wantprop(bodyprops, "language")) {
        json_t *jlanguage = json_null();
        json_t *jrawheader = _email_get_header(msg, part, "content-language",
                                               HEADER_FORM_RAW, /*all*/0);
        if (JNOTNULL(jrawheader)) {
            /* Split by space and comma and aggregate into array */
            const char *s = json_string_value(jrawheader);
            jlanguage = json_array();
            int i;
            char *tmp = charset_unfold(s, strlen(s), 0);
            strarray_t *ls = strarray_split(tmp, "\t ,", STRARRAY_TRIM);
            for (i = 0; i < ls->count; i++) {
                json_array_append_new(jlanguage, json_string(strarray_nth(ls, i)));
            }
            strarray_free(ls);
            free(tmp);
        }
        if (!json_array_size(jlanguage)) {
            json_decref(jlanguage);
            jlanguage = json_null();
        }
        json_object_set_new(jbodypart, "language", jlanguage);
        json_decref(jrawheader);
    }


    /* location */
    if (jmap_wantprop(bodyprops, "location")) {
        json_object_set_new(jbodypart, "location", part->location ?
                json_string(part->location) : json_null());
    }

    /* subParts */
    if (!strcmp(part->type, "MULTIPART")) {
        json_t *subparts = json_array();
        int i;
        for (i = 0; i < part->numparts; i++) {
            struct body *subpart = part->subpart + i;
            json_array_append_new(subparts,
                    _email_get_bodypart(req, args, msg, subpart));

        }
        json_object_set_new(jbodypart, "subParts", subparts);
    }
    else if (jmap_wantprop(bodyprops, "subParts")) {
        json_object_set_new(jbodypart, "subParts", json_array());
    }


    /* FastMail extension properties */
    // if (jmap_wantprop(bodyprops, "imageSize")) {
    //     json_t *imagesize = json_null();
    //     if (msg->mr && msg->imagesize_by_part == NULL) {
    //         /* This is the first attempt to read the vendor annotation.
    //          * Load the annotation value, if any, for top-level messages.
    //          * Use JSON null for an unsuccessful attempt, so we know not
    //          * to try again. */
    //         msg->imagesize_by_part = _email_read_jannot(req, msg->mr,
    //                 "/vendor/messagingengine.com/imagesize", 1);
    //         if (!msg->imagesize_by_part)
    //             msg->imagesize_by_part = json_null();
    //     }
    //     imagesize = json_object_get(msg->imagesize_by_part, part->part_id);
    //     json_object_set(jbodypart, "imageSize", imagesize ? imagesize : json_null());
    // }
    if (jmap_wantprop(bodyprops, "isDeleted")) {
        json_object_set_new(jbodypart, "isDeleted",
                json_boolean(!strcmp(part->type, "TEXT") &&
                             !strcmp(part->subtype, "X-ME-REMOVED-FILE")));
    }

    buf_free(&buf);
    return jbodypart;
}

static json_t * _email_get_bodyvalue(struct body *part,
                                     const struct buf *msg_buf,
                                     size_t max_body_bytes,
                                     int is_html)
{
    json_t *jbodyvalue = NULL;
    int is_encoding_problem = 0;
    int is_truncated = 0;
    struct buf buf = BUF_INITIALIZER;

    /* Decode into UTF-8 buffer */
    char *raw = _decode_to_utf8(part->charset_id,
            msg_buf->s + part->content_offset,
            part->content_size, part->encoding,
            &is_encoding_problem);
    if (!raw) goto done;

    /* In-place remove CR characters from buffer */
    size_t i, j, rawlen = strlen(raw);
    for (i = 0, j = 0; j < rawlen; j++) {
        if (raw[j] != '\r') raw[i++] = raw[j];
    }
    raw[i] = '\0';

    /* Initialize return value */
    buf_initm(&buf, raw, rawlen);

    /* Truncate buffer */
    if (buf_len(&buf) && max_body_bytes && max_body_bytes < buf_len(&buf)) {
        /* Cut of excess bytes */
        buf_truncate(&buf, max_body_bytes);
        is_truncated = 1;
        /* Clip to sane UTF-8 */
        /* XXX do not split between combining characters */
        const unsigned char *base = (unsigned char *) buf_base(&buf);
        const unsigned char *top = base + buf_len(&buf);
        const unsigned char *p = top - 1;
        while (p >= base && ((*p & 0xc0) == 0x80))
            p--;
        if (p >= base) {
            ssize_t have_bytes = top - p;
            ssize_t need_bytes = 0;
            unsigned char hi_nibble = *p & 0xf0;
            switch (hi_nibble) {
                case 0xf0:
                    need_bytes = 4;
                    break;
                case 0xe0:
                    need_bytes = 3;
                    break;
                case 0xc0:
                    need_bytes = 2;
                    break;
                default:
                    need_bytes = 1;
            }
            if (have_bytes < need_bytes)
                buf_truncate(&buf, p - base);
        }
        else {
            buf_reset(&buf);
        }
    }

    /* Truncate HTML */
    if (buf_len(&buf) && max_body_bytes && is_html) {
        /* Truncate any trailing '<' start tag character without closing '>' */
        const char *base = buf_base(&buf);
        const char *top  = base + buf_len(&buf);
        const char *p;
        for (p = top - 1; *p != '>' && p >= base; p--) {
            if (*p == '<') {
                buf_truncate(&buf, p - base + 1);
                is_truncated = 1;
                break;
            }
        }
    }

done:
    jbodyvalue = json_pack("{s:s s:b s:b}",
            "value", buf_cstring(&buf),
            "isEncodingProblem", is_encoding_problem,
            "isTruncated", is_truncated);
    buf_free(&buf);
    return jbodyvalue;
}

static int _email_get_bodies(jmap_req_t *req,
                             struct email_getargs *args,
                             struct cyrusmsg *msg,
                             json_t *email)
{
    struct emailbodies bodies = EMAILBODIES_INITIALIZER;
    hash_table *props = args->props;
    int r = 0;

    const struct body *part;
    if (msg->rfc822part) {
        part = msg->rfc822part->subpart;
    }
    else {
        r = _cyrusmsg_need_part0(msg);
        if (r) return r;
        part =  msg->part0;
    }

    /* Dissect message into its parts */
    r = jmap_emailbodies_extract(part, &bodies);
    if (r) goto done;

    /* bodyStructure */
    if (jmap_wantprop(props, "bodyStructure")) {
        json_object_set_new(email, "bodyStructure",
                _email_get_bodypart(req, args, msg, part));
    }

    /* bodyValues */
    if (jmap_wantprop(props, "bodyValues")) {
        json_t *body_values = json_object();
        /* Determine which body value parts to fetch */
        int i;
        ptrarray_t parts = PTRARRAY_INITIALIZER;
        if (args->fetch_text_body || args->fetch_all_body) {
            for (i = 0; i < bodies.textlist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.textlist, i));
        }
        if (args->fetch_html_body || args->fetch_all_body) {
            for (i = 0; i < bodies.htmllist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.htmllist, i));
        }
        if (parts.count) {
            r = _cyrusmsg_need_mime(msg);
            if (r) goto done;
        }
        /* Fetch body values */
        for (i = 0; i < parts.count; i++) {
            struct body *part = ptrarray_nth(&parts, i);
            if (strcmp("TEXT", part->type)) {
                continue;
            }
            if (part->part_id && json_object_get(body_values, part->part_id)) {
                continue;
            }
            json_object_set_new(body_values, part->part_id,
                    _email_get_bodyvalue(part, msg->mime, args->max_body_bytes,
                                         !strcmp("HTML", part->subtype)));
        }
        ptrarray_fini(&parts);
        json_object_set_new(email, "bodyValues", body_values);
    }

    /* textBody */
    if (jmap_wantprop(props, "textBody")) {
        json_t *text_body = json_array();
        int i;
        for (i = 0; i < bodies.textlist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.textlist, i);
            json_array_append_new(text_body,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "textBody", text_body);
    }

    /* htmlBody */
    if (jmap_wantprop(props, "htmlBody")) {
        json_t *html_body = json_array();
        int i;
        for (i = 0; i < bodies.htmllist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.htmllist, i);
            json_array_append_new(html_body,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "htmlBody", html_body);
    }

    /* attachments */
    if (jmap_wantprop(props, "attachments")) {
        json_t *attachments = json_array();
        int i;
        for (i = 0; i < bodies.attslist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.attslist, i);
            json_array_append_new(attachments,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "attachments", attachments);
    }

    /* calendarEvents -- non-standard */
    // if (jmap_wantprop(props, "calendarEvents")) {
    //     json_t *calendar_events = json_object();
    //     int i;
    //     for (i = 0; i < bodies.attslist.count; i++) {
    //         struct body *part = ptrarray_nth(&bodies.attslist, i);
    //         /* Process text/calendar attachments and files ending with .ics */
    //         if (strcmp(part->type, "TEXT") || strcmp(part->subtype, "CALENDAR")) {
    //             int has_ics_attachment = 0;
    //             struct param *param = part->disposition_params;
    //             while (param) {
    //                 if (!strcasecmp(param->attribute, "FILENAME")) {
    //                     size_t len = strlen(param->value);
    //                     if (len > 4 && !strcasecmp(param->value + len-4, ".ICS")) {
    //                         has_ics_attachment = 1;
    //                     }
    //                 }
    //                 param = param->next;
    //             }
    //             if (!has_ics_attachment)
    //                 continue;
    //         }
    //         /* Parse decoded data to iCalendar object */
    //         r = _cyrusmsg_need_mime(msg);
    //         if (r) goto done;
    //         char *decbuf = NULL;
    //         size_t declen = 0;
    //         const char *rawical = charset_decode_mimebody(msg->mime->s + part->content_offset,
    //                 part->content_size, part->charset_enc, &decbuf, &declen);
    //         if (!rawical) continue;
    //         struct buf buf = BUF_INITIALIZER;
    //         buf_setmap(&buf, rawical, declen);
    //         icalcomponent *ical = ical_string_as_icalcomponent(&buf);
    //         buf_free(&buf);
    //         free(decbuf);
    //         if (!ical) continue;
    //         /* Parse iCalendar object to JSCalendar */
    //         json_t *jsevents = jmapical_tojmap_all(ical, NULL);
    //         if (json_array_size(jsevents)) {
    //             json_object_set_new(calendar_events, part->part_id, jsevents);
    //         }
    //         icalcomponent_free(ical);
    //     }
    //     if (!json_object_size(calendar_events)) {
    //         json_decref(calendar_events);
    //         calendar_events = json_null();
    //     }
    //     json_object_set_new(email, "calendarEvents", calendar_events);
    // }

    /* hasAttachment */
    if (jmap_wantprop(props, "hasAttachment")) {
        int has_att = 0;
        if (msg->rfc822part == NULL) {
            assert(0); // EDITED
            // msgrecord_hasflag(msg->mr, JMAP_HAS_ATTACHMENT_FLAG, &has_att);
        }
        else {
            has_att = bodies.attslist.count > 0;
        }
        json_object_set_new(email, "hasAttachment", json_boolean(has_att));
    }

    /* preview */
    if (jmap_wantprop(props, "preview")) {
        // const char *preview_annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
        if (0 /*preview_annot && msg->rfc822part == NULL*/) { // EDITED
            // json_t *preview = _email_read_jannot(req, msg->mr, preview_annot, /*structured*/0);
            // json_object_set_new(email, "preview", preview ? preview : json_string(""));
        }
        else {
            r = _cyrusmsg_need_mime(msg);
            if (r) goto done;
            /* TODO optimise for up to PREVIEW_LEN bytes */
            char *text = _emailbodies_to_plain(&bodies, msg->mime);
            if (!text) {
                char *html = _emailbodies_to_html(&bodies, msg->mime);
                if (html) text = _html_to_plain(html);
                free(html);
            }
            if (text) {
                size_t len = 200; //config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH); // EDITED
                char *preview = _email_extract_preview(text, len);
                json_object_set_new(email, "preview", json_string(preview));
                free(preview);
                free(text);
            }
        }
    }

done:
    jmap_emailbodies_fini(&bodies);
    return r;
}

static int _email_from_msg(void *req,
                           struct email_getargs *args,
                           struct cyrusmsg *msg,
                           json_t **emailptr)
{
    json_t *email = json_object();
    int r = 0;

    r = _email_get_meta(req, args, msg, email);
    if (r) goto done;

    r = _email_get_headers(req, args, msg, email);
    if (r) goto done;

    r = _email_get_bodies(req, args, msg, email);
    if (r) goto done;

    *emailptr = email;
done:

    if (r) json_decref(email);
    return r;
}


static int _email_from_buf(/*jmap_req_t*/ void *req,
                           struct email_getargs *args,
                           const struct buf *buf,
                           const char *encoding,
                           json_t **emailptr)
{
    struct buf mybuf = BUF_INITIALIZER;
    buf_setcstr(&mybuf, "Content-Type: message/rfc822\r\n");
    if (encoding) {
        if (!strcasecmp(encoding, "BASE64")) {
            char *tmp = NULL;
            size_t tmp_size = 0;
            charset_decode_mimebody(buf_base(buf), buf_len(buf),
                    ENCODING_BASE64, &tmp, &tmp_size);
            buf_appendcstr(&mybuf, "Content-Transfer-Encoding: binary\r\n");
            /* Append base64-decoded body */
            buf_appendcstr(&mybuf, "\r\n");
            buf_appendmap(&mybuf, tmp, tmp_size);
            free(tmp);
        }
        else {
            buf_appendcstr(&mybuf, "Content-Transfer-Encoding: ");
            buf_appendcstr(&mybuf, encoding);
            buf_appendcstr(&mybuf, "\r\n");
            /* Append encoded body */
            buf_appendcstr(&mybuf, "\r\n");
            buf_append(&mybuf, buf);
        }
    }
    else {
        /* Append raw body */
        buf_appendcstr(&mybuf, "\r\n");
        buf_append(&mybuf, buf);
    }

    struct cyrusmsg *msg = NULL;
    int r = _cyrusmsg_from_buf(&mybuf, &msg);
    if (!r) r = _email_from_msg(req, args, msg, emailptr);
    buf_free(&mybuf);
    _cyrusmsg_free(&msg);
    return r;
}

int jmap_email_from_buf(const struct buf *buf,
                           const char *encoding,
                           json_t **emailptr) {

    struct email_getargs getargs = _EMAIL_GET_ARGS_INITIALIZER;
    getargs.props = &_email_parse_default_props;
    if (getargs.props->size == 0) {
        _email_init_default_props(getargs.props);
    }

    getargs.bodyprops = &_email_get_default_bodyprops;
    if (getargs.bodyprops->size == 0) {
        _email_init_default_props(getargs.bodyprops);
    }

    getargs.fetch_all_body = 1;

    return _email_from_buf(NULL, &getargs, buf, encoding, emailptr);
}
