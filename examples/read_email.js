const {ready, envelope_to_jmap} = require('..')
const fs = require('fs')

const file = fs.readFileSync(process.argv[2] || 'some.eml')

ready.then(() => {
  const {json} = envelope_to_jmap(file)

  // json contains {to: [...], from: [...], cc, subject, headers, 
  console.log('From: ', json.from, 'To', json.to, 'subject', json.subject)
  console.log('text body:', json.bodyValues[json.textBody[0].partId].value)
  //console.log('html body:', json.bodyValues[json.htmlBody[0].partId].value)
})
