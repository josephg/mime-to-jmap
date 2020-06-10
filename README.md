# Email to JMAP tools

This is a reference implementation of a [JMAP](https://jmap.io/spec-mail.html)-compatible email parser, implemented as a javascript library, built with wasm.

[Try it online](https://josephg.com/mail-viewer/)

The code is a bit of a mess - most of the implementation here is C code which has been ripped out of [cyrus-imap](https://github.com/cyrusimap/cyrus-imapd/) since thats already maintained and used for JMAP at Fastmail. The C code compiles to wasm, and does all the heavy lifting to extract usable jmap-compatible structure information, HTML and text bodies and file attachments.

This is needed because most (all?) of the email parsing libraries on npm are missing features:

- Many JS email libraries pack the headers into an object, which results in the headers being reordered arbitrarily. I'm very sad to say, the order of email headers matters in many cases.
- In their truest form, emails actually contain a tree of message objects. Most email parsing libraries are too keen to merge message envelopes together.
- The cyrus email parser used here produces clean HTML from *any* email for rendering in a browser-like context. (Its the same code that renders emails for fastmail). It also produces meaningful text snippets - even for html-heavy emails.
- We have full internationalization support

In general, the email spec is [nightmare fuel](https://www.youtube.com/watch?v=4s9IjkMAmns). This library attempts to tame the horror show.

There are two main pieces to this library:

- A WASM-compiled bundle which bundles [cyrus-imap](https://github.com/cyrusimap/cyrus-imapd/)'s JMAP handling code. Cyrus is used in production with millions of emails, so this code should be pretty reliable and stable.
- Some simple javascript code to interact with the native module, and iterate through emails in an mboxrd file. I've only really exercised this thoroughly with emails extracted from gmail. There's a good chance of bugs lurking here.

The mbox handling may contain some bugs simply by virtue of being young code. Please file issues when you find them.


## Parsing RFC8222 email objects

To convert mime objects into JMAP-compatible JSON use `envelope_to_jmap(content: ArrayBufferView | Buffer | string, [options])`. This function returns `{json, [attachments]}` where json is a [JMAP email object](https://jmap.io/spec-mail.html#properties-of-the-email-object) with all default fields and full header information.

The parser code is synchronous, but unfortunately because the guts of this library is in a wasm module, you have to wait on a ready promise before you can call any methods from this library.

```javascript
const {ready, envelope_to_jmap} = require('mime-to-jmap')
const fs = require('fs')

const file = fs.readFileSync('some.eml')

ready.then(() => {
  const {json} = envelope_to_jmap(file)

  // json contains {to: [...], from: [...], cc, subject, headers, ... etc as per the jmap spec}
  console.log('From: ', json.from, 'To', json.to, 'subject', json.subject)
  console.log('text body:', json.bodyValues[json.textBody[0].partId].value)

  // Or the HTML body:
  //console.log('html body:', json.bodyValues[json.htmlBody[0].partId].value)
})
```

The main entrypoint for this library is `envelope_to_jmap()`. The method takes a buffer with the email data and an optional options object. If supplied, the options object takes the following fields:

- **attachments**: (*boolean*, default *false*) By default, `envelope_to_jmap` will not parse out email attachments beyond text and HTML sections. If the attachments flag is set, `envelope_to_jmap` will return an `arguments` field, which is an object mapping from blob IDs to the attachment data itself. Note the metadata for each attachment is returned through the regular JSON email body object. This data is attached separately to fit with the jmap data model. See [examples/extract_attachments.js](https://github.com/josephg/mime-to-jmap/blob/master/examples/extract_attachments.js) for an example of how to extract this data in practice. The attachment data is returned as an ArrayBuffer because the node buffer class isn't available in the browser.
- **want_headers**: (*string[]*, default *[]*) A list of extra custom headers for `envelope_to_jmap` to parse and return in the returned JSON object. Currently all raw headers are returned by default anyway, but the library can parse custom headers into standard objects for many types of data. For example, to fetch unsubscribe links, pass `['header:List-Unsubscribe:asURLs']` here and the corresponding header will be automatically extracted and decoded to URLs. Values extracted this way are put on the returned JMAP object using the supplied search string as their key. (Eg via `json['header:List-Unsubscribe:asURLs']`).
- **want_bodyheaders**: (*string[]*, default *[]*) This is functionally the same as *want_headers* above, but instead of looking for headers on the root object, this looks for the named header in each body inside the email envelope.

> *Note:* The returned object is slightly non-spec compliant as JMAP objects are expected to have a receivedAt date, but we can't calculate that value from the mime object alone - it needs to be filled in by the receiving email server. As a result, the `json.receivedAt` property will be null on the returned object.



## Parsing emails in MBOX files

This library also comes with some utility methods for pulling emails out of [mbox files](https://en.wikipedia.org/wiki/Mbox) (using the *mboxrd* format). This has been tested with emails from Google Takeout, but there may be bugs importing emails from other systems. (Email is a hot mess.)

```javascript
const {ready, mbox_each, mbox_to_eml, envelope_to_jmap} = require('mime-to-jmap')
const fs = require('fs')

process.on('unhandledRejection', e => {
  throw e
})

;(async () => {
  await ready

  const filename = process.argv[2] || 'archive.mbox'
  const stream = fs.createReadStream(filename)

  for await (const msg of mbox_each(stream)) {
    const {body, mboxFromAddress, receivedAt} = mbox_to_eml(msg)
    const {json} = envelope_to_jmap(body)

    json.receivedAt = receivedAt
    
    console.log('Email', mboxFromAddress, 'from', json.from[0].name, 'subject', json.subject)
  }
})()
```

Note that the mbox format contains two extra fields for each email:

- From address
- IMAP timestamp

Gmail (and other?) systems use the 'from' address to list a system-internal identifier for the email message.

The timestamp is the time the email was received on the server, so if you're going to serve these messages over jmap (or another protocol), you can assign the timestamp into the jmap JSON object. This is returned as an ISO string, as expected of JMAP.


## FAQ

### Why is the bundle so big?

Also note the wasm compiled bundle (which can be downloaded from npm) is quite large for use in the browser, sitting at 735k gzipped. The main reason for this is that the library bundles parts of [libicu](http://site.icu-project.org/home) for internationalization support. So the wasm file contains character encoding tables from the pre-unicode world.

There are two ways we could shrink the library:

- We could build without support for all legacy character encodings (so stop supporting emails which aren't encoded to ASCII, Latin-1 or a UTF-* variant)
- Use libicu from the execution environment instead of bundled copies. All modern operating systems (and browsers) already have the character encodings we need. We could rewrite the charset code to call out to javascript's [String#normalize](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/normalize) and [TextDecoder](https://nodejs.org/api/util.html#util_class_util_textdecoder) to convert obscure formats to unicode.

Please vote for fixing this by filing a github issue if this matters to you. Otherwise I'll assume nobody minds.


### How do I turn email objects into threads?

I've written some simple proof-of-concept code for processing a group of emails into a set of threads [in mail-viewer](https://github.com/josephg/mail-viewer/blob/master/src/processMail.ts).

Feel free to use that code and adapt it to your needs.


### How do I render jmap emails safely in a browser?

Take a look at @neilj's [jmap-demo-webmail](https://github.com/jmapio/jmap-demo-webmail/blob/master/app/drawHTML.js), which uses [dompurify](https://www.npmjs.com/package/dompurify) to clean up the `message.htmlBody` part in a message.


## Compiling from source

Its a pain in the neck to compile from source. You need:

- Emscripten
- A fork of libicu that can be built to wasm. Get [@mabel's libicu fork](https://github.com/mabels/icu) here.

Build libicu from the `wasm32` branch using emscripten (`emconfigure ./configure`)

Then change CMakeLists.txt in mime-to-jmap to point to your compiled libicu, then run `make`.

I recommend most users just using the [prebuilt version in npm](https://www.npmjs.com/package/mime-to-jmap).


## LICENSE

This library contains code from Cyrus, which can trace its origins back to the dark days at CMU. See COPYING_cyrus for the cyrus license.

All other code is copyright 2019 Joseph Gentle

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 