const {ready, envelope_to_jmap} = require('..')
const fs = require('fs')

const file = fs.readFileSync(process.argv[2] || 'some.eml')

// *** NOTE: Running this will actually save attachments in the named file to your hard disk.
ready.then(() => {
  const {json, attachments} = envelope_to_jmap(file, {
    want_headers: ['header:X-Gmail-Labels:asText', 'header:List-Unsubscribe:asURLs'],
    with_attachments: true,
  })

  console.log('Gmail thread ids:', json['header:X-Gmail-Labels:asText'])
  console.log('Unsubscribe link:', json['header:List-Unsubscribe:asURLs'])

  // Attachments is a content-addressable map from blobId => Buffer with the attachment's contents.
  // Metadata about each attachment in json.attachments[blobId].{type, name, disposition, ...}.

  for (const {name, blobId, type} of json.attachments) {
    const data = attachments[blobId]
    console.log('Saving file', name, data.length, 'of type', type) // type is a mime type, eg 'image/jpeg'.
    fs.writeFileSync('attachment_' + name, data) // name is the filename listed in the email
  }
})
