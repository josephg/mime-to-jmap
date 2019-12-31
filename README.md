# Email to JMAP tools

> *STATUS:* Works, but its a bit of a hot mess. This is mostly at a proof of concept level of maturity.

This is a set of helper utilities to parse email messages to [JMAP](https://jmap.io/spec-mail.html)-compatible JSON objects.

The implementation is a mess - most of the implementation here is C code which has been ripped out of [cyrus-imap](https://github.com/cyrusimap/cyrus-imapd/) since thats already maintained and used for JMAP at Fastmail. The C code can be compiled to wasm and run to extract usable jmap-compatible structure information, HTML and text bodies and file attachments.

## Parsing RFC8222 email objects

This library covers a few different use cases.

To convert mime objects into JMAP-compatible JSON use `envelope_to_jmap(content: Buffer | string, wantAttachments: boolean)`. This function returns `{json, [attachments]}` where json is a [JMAP email object](https://jmap.io/spec-mail.html#properties-of-the-email-object) with all default fields and full header information.

Unfortunately because the guts of this library is in a wasm module, to use this properly you have to wait on a ready promise.

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

- **envelope_to_jmap(data: Buffer, opts?: Options) => {json, attachments?}**

The main entrypoint for this library is `envelope_to_jmap()`. The method takes a buffer with the email data and an optional options object. If supplied, the options object takes the following fields:

- **attachments**: (*boolean*, default *false*) By default, `envelope_to_jmap` will not parse out email attachments beyond text and HTML sections. If the attachments flag is set, `envelope_to_jmap` will return an `arguments` field, which is an object mapping from blob IDs to the attachment data itself. Note the metadata for each attachment is returned through the regular JSON email body object. This data is attached separately to fit with the jmap data model. See [examples/extract_attachments.js](https://github.com/josephg/mime-to-jmap/blob/master/examples/extract_attachments.js) for an example of how to use this data in practice.
- **want_headers**: (*string[]*, default *[]*) A list of extra custom headers for `envelope_to_jmap` to parse and return in the returned JSON object. Currently all raw headers are returned by default anyway, but the library can parse custom headers into standard objects for many types of data. For example, to fetch unsubscribe links, pass `['header:List-Unsubscribe:asURLs']` here and the corresponding header will be automatically extracted and decoded to URLs. Values extracted this way are put on the returned JMAP object using the supplied search string as their key. (Eg via `json['header:List-Unsubscribe:asURLs']`).
- **want_bodyheaders**: (*string[]*, default *[]*) This is functionally the same as *want_headers* above, but instead of looking for headers on the root object, this looks for the named header in each body inside the email envelope.

> *Note:* The returned object is slightly non-spec compliant as JMAP objects are expected to have a receivedAt date, but we can't calculate that value from the mime object alone. As a result, the `json.receivedAt` property will always be null on the returned object.


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


