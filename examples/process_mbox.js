const {ready, mbox_each, mbox_to_eml, envelope_to_jmap} = require('..')
const fs = require('fs')

process.on('unhandledRejection', e => {
  throw e
})

;(async () => {
  await ready

  const filename = process.argv[2] || 'testcases/devtest.mbox'
  const stream = fs.createReadStream(filename)

  for await (const msg of mbox_each(stream)) {
    const {body, mboxFromAddress, receivedAt} = mbox_to_eml(msg)
    const {json} = envelope_to_jmap(body)

    json.receivedAt = receivedAt
    
    console.log('Email', mboxFromAddress, 'from', json.from[0].name, 'subject', json.subject)
    console.dir(json)
  }
})()

