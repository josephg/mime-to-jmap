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

By default, `envelope_to_jmap` will not parse out email attachments beyond text and HTML sections. To fetch attachments, pass `true` as the second argument. This will populate `attachments` in the return value, which is an object which maps blob IDs to the attachment data itself. Note the metadata for each attachment is returned through the regular JSON email body object.

```javascript
const {ready, envelope_to_jmap} = require('mime-to-jmap')
const fs = require('fs')

const file = fs.readFileSync('some.eml')

// *** NOTE: Running this will actually save attachments in the named file to your hard disk.
ready.then(() => {
  const {json, attachments} = envelope_to_jmap(file, true)

  // Attachments is a content-addressable map from blobId => Buffer with the attachment's contents.
  // Metadata about each attachment in json.attachments[blobId].{type, name, disposition, ...}.

  for (const {name, blobId, type} of json.attachments) {
    const data = attachments[blobId]
    console.log('Saving file', name, data.length, 'of type', type) // type is a mime type, eg 'image/jpeg'.
    fs.writeFileSync('attachment_' + name, data) // name is the filename listed in the email
  }
})
```

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


