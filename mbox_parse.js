const fs = require('fs')
const {mbox_message_to_jmap, ready} = require('./index.js')

process.on('unhandledRejection', e => {
  throw e
})

const process_message = chunk => {
  // console.log('XXX', chunk.length, chunk.slice(0, 30))
  // if (!chunk.startsWith('From 1505721886588449464@xxx S')) return
  // console.log('\n\n========== MESSAGE ===========\n\n' + chunk)
  // fs.writeFileSync('last.eml', chunk)
  const {mboxFromAddress, json} = mbox_message_to_jmap(chunk, false)
  // console.log(mboxFromAddress)
}

async function chunkMBox(readable) {
  await ready
  // let data = ''
  // let message_start = -1
  let body = ''
  for await (const chunk of readable) {
    // data += chunk
    body += chunk
    while (true) {
      const m = body.match(/^From /m)
      if (m == null) break

      const idx = m.index 
      if (idx > 0) { // Ignore first empty message
        const mbox_msg = 'From ' + body.slice(0, idx)
        // console.log('process_message!', idx, `'${mbox_msg}'`)
        process_message(mbox_msg)
        // process_message(data.slice(message_start, idx))
      }
      body = body.slice(idx + 'From '.length)
      // message_start = idx
    }
  }
  // And when we reach the end, whatever is left is a message too.
  if (body !== '') {
    const mbox_msg = 'From ' + body
    // console.log('process_message!', `'${mbox_msg}'`)
    process_message(mbox_msg)
  }
}

// console.log(process.argv)
chunkMBox(fs.createReadStream(process.argv[2] || '/Users/josephg/Downloads/Takeout 3/Mail/devtest.mbox', {
  encoding: 'utf8'
}))