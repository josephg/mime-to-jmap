const {ready, mbox_each_progress, mbox_to_eml, envelope_to_jmap} = require('..')
const cliprogress = require('cli-progress')
const fs = require('fs')

process.on('unhandledRejection', e => {
  throw e
})

;(async () => {
  await ready

  const filename = process.argv[2] || 'testcases/devtest.mbox'

  const {size} = fs.statSync(filename)
  const stream = fs.createReadStream(filename)

  const bar = new cliprogress.SingleBar({fps: 1}, cliprogress.Presets.shades_classic)
  bar.start(size, 0)

  for await (const {msg, progress} of mbox_each_progress(stream)) {
    const {body, mboxFromAddress, receivedAt} = mbox_to_eml(msg)
    const {json} = envelope_to_jmap(body)

    json.receivedAt = receivedAt
    
    bar.update(progress)
  }

  bar.stop()
})()

