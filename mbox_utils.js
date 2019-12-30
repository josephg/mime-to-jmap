const assert = require('assert')
const fs = require('fs')
const {envelope_to_jmap, ready} = require('./index.js')


async function* mbox_each_progress(readable) {
  // We're scanning for the byte range '\nFrom ', which is [0a 46 72 6f 6d 20].
  let start = 0
  let chunks = [] // After the first iteration length >= 1.
  let rbuf = Buffer.alloc(6) // ring buffer with the last 6 bytes in the prev chunk
  let rnextidx = 0

  let progress = 0

  const getChunk = (endPos) => {
    // console.log('getChunk', endPos)
    // endPos is the position of the 'F' in 'From ' in the next email, in the last chunk.
    // Could be negative if the email ends in the previous chunk.
    
    let endChunkIdx = chunks.length - 1
    while (endPos < 0) {
      endChunkIdx--
      endPos += chunks[endChunkIdx].length
    }

    // The chunk goes from chunks[0][start] to chunks[len-1][endPos].
    if (endChunkIdx > 0) {
      // Slow path. We'll have to copy the chunk into a single buffer and yield that.
      // We could have another fastpath if the whole email is in the previous chunk but eh.

      // Calculate length. We could probably precompute this but its no big.
      let len = chunks[0].length - start
      let pos = len
      for (let i = 1; i < endChunkIdx; i++) {
        len += chunks[i].length
      }
      len += endPos // Correct even if endpos is negative

      const b = Buffer.alloc(len)
      chunks[0].copy(b, 0, start) // src.copy(target, targetStart?, sourceStart?, sourceEnd?)
      for (let i = 1; i < endChunkIdx; i++) {
        chunks[i].copy(b, pos)
        pos += chunks[i].length
      }
      chunks[endChunkIdx].copy(b, pos, 0, endPos)
      
      for (let i = 0; i < endChunkIdx; i++) {
        chunks.shift()
      }
      progress += len
      start = endPos
      return b
    } else {
      const b = chunks[0].slice(start, endPos)
      progress += endPos - start
      start = endPos
      return b
    }
  }

  // debugger
  for await (const newChunk of readable) {
    // console.log('chunk', newChunk.length)
    // body += chunk
    chunks.push(newChunk)
    // Scan for '\nFrom ' in the chunk list

    for (let ci = 0; ci < newChunk.length; ci++) {
      rbuf[rnextidx] = newChunk[ci]
      if (rbuf[rnextidx] === 0x20
        && rbuf[(rnextidx+1)%6] === 0x0a
        && rbuf[(rnextidx+2)%6] === 0x46
        && rbuf[(rnextidx+3)%6] === 0x72
        && rbuf[(rnextidx+4)%6] === 0x6f
        && rbuf[(rnextidx+5)%6] === 0x6d) {
          const b = getChunk(ci - 4) // Point at the start of 'From'.
          // console.log('found a message', start, 0, chunks.length-1, ci, b.length)
          // if (b.toString().startsWith('From 1499798469943408013@xxx')) debugger
          yield {msg: b, progress}
      }
      rnextidx = (rnextidx + 1) % 6
    }
  }
  // And when we reach the end, whatever is left is a message too.
  if (chunks.length) {
    // const mbox_msg = 'From ' + body
    // console.log('process_message!', `'${mbox_msg}'`)
    // process_message(mbox_msg)
    yield {msg: getChunk(chunks[chunks.length-1].length), progress}
  }
}

const splitFirst = (s, pattern) => {
  const idx = s.indexOf(pattern)
  if (idx < 0) return [s]
  else return [s.slice(0, idx), s.slice(idx + 1)]
}

// This trims extraneous '>' in '\n>+From ' patterns in mboxrd files
const pattern = Buffer.from('>From ')
const mboxrd_trim_from = (buf, startIdx) => {
  let searchPos = startIdx + 1
  let shift = 0
  let copyTo = -1

  // Here we'll scan and compact the buffer inline using memmove.

  outer: while (searchPos < buf.length) {
    // We're looking for '\n>+From ' and we want to strip one of the > characters when we find it.
    const gtPos = buf.indexOf(pattern, searchPos) // Index of the last >.
    if (gtPos < 0) break // No more instances of the pattern were found. We're done.
    
    searchPos = gtPos + 6 // Next time look after this instance of the pattern.

    // Check that the pattern is preceeded by /\n>>>*/
    let p = gtPos - 1
    while (true) {
      if (p < 0) continue outer
      const c = buf[p]
      p--
      if (c === 0x3e) continue // 0x3e is '>'. Ignore.
      if (c === 0x0a) {
        // Found the pattern.
        break
      } else continue outer
    }

    if (shift) {
      // assert(buf[copyTo] === 0x3e) // >
      assert(buf[p+1] === 0x0a) // \n
      buf.copy(buf, copyTo, copyTo+shift, p+2)
      // console.log('trim', shift)
    }
    copyTo = p + 2 - shift
    shift++
  }
  
  if (shift) {
    // assert(buf[copyTo] === 0x3e) // >
    buf.copy(buf, copyTo, copyTo+shift)
    // console.log('trim', shift, copyTo)
  }

  return buf.slice(startIdx, buf.length - shift)
}

const mbox_to_eml = (mbox_buf) => {
  // The mbox string always starts with 'From '
  
  // Find the first line
  const end_line_1 = mbox_buf.indexOf('\n') // Its actually /r/n but this is fine.
  assert(end_line_1 > 0)
  const line_1 = mbox_buf.slice(0, end_line_1 - 1).toString() // ignore the '\r' as well.
  // console.log(line_1)
  assert(line_1.startsWith('From '), 'mbox message does not start with from line')
  
  // The first line is 'From <id> <servertime>'. There are no spaces in the id.
  const id_and_time = line_1.slice('From '.length).toString('ascii')
  const [mboxFromAddress, time_str] = splitFirst(id_and_time, ' ')
  const receivedAt = (new Date(time_str)).toISOString()

  // const start_line_2 = mbox_buf.slice(end_line_1 + 1)

    // Check the message string matches what we expect.
    // const msg_str = mbox_buf.slice(end_line_1 + 1).toString('ascii')
    // const msg_str_sub = msg_str.replace(/^>(>*From )/mg, '$1')
    
  // Now we need to find \r\n>*From and remove one of the > characters.
  // I want to keep the data as a buffer, so I'm doing this the old fashioned way.
  // Could pretty easily do this in C instead.
  const body = mboxrd_trim_from(mbox_buf, end_line_1 + 1)
  // console.log(body.toString())

    // assert.deepStrictEqual(body.toString('ascii'), msg_str_sub)

  // const {json, attachments} = envelope_to_jmap(msg_str_sub, with_attachments)
  // json.receivedAt = receivedAt
  
  // For gmail, the mbox from address contains the ID of the message itself.
  // return {mboxFromAddress, json, attachments}
  return {body, mboxFromAddress, receivedAt}
}

function *mbox_each(stream) {
  for await (const {msg} of mbox_each_progress(stream)) {
    yield msg
  }
}

module.exports = {mbox_each, mbox_each_progress, mbox_to_eml}

if (require.main === module) {
//   const t = s => trimFromPatterns(Buffer.from(s, 'utf-8'), 0).toString()

//   console.log(t(`
// >From asdf
// >>>From asdf

// abc>From xyz
// >From asdf`))


  ;(async () => {
    process.on('unhandledRejection', e => {
      throw e
    })

    await ready

    const cliprogress = require('cli-progress')

    const filename = process.argv[2] || '/Users/josephg/Downloads/Takeout 3/Mail/devtest.mbox'
    const {size} = fs.statSync(filename)

    const bar = new cliprogress.SingleBar({fps: 1}, cliprogress.Presets.shades_classic)
    const iter = mbox_each_progress(fs.createReadStream(filename, {
      // encoding: 'utf8'
    }))

    bar.start(size, 0)

    let num = 0
    for await (const {msg, progress} of iter) {
      const {body} = mbox_to_eml(msg)
      envelope_to_jmap(body, false)
      
      bar.update(progress)
      // num++

      // if (num >= 3000) break
      // console.log(msg.length)
      // console.log('--------------------\n' + msg.toString() + '\n-------')
      // process_message(msg)
    }
    bar.stop()
  })()
}

// console.log(process.argv)
// chunkMBox(fs.createReadStream(process.argv[2] || '/Users/josephg/Downloads/Takeout 3/Mail/devtest.mbox', {
//   encoding: 'utf8'
// }))