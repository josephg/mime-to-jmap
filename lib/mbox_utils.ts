
const assert = (cond: any, str?: string) => {
  if (!cond) {
    console.error(new Error().stack)
    throw Error(str || 'assertion failed')
  }
}

const as_uint8_array = (buf: ArrayBufferView) => (
  buf instanceof Uint8Array
    ? buf
    : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
)

export async function* mbox_each_progress(readable: AsyncIterable<ArrayBufferView>) {
  // We're scanning for the byte range '\nFrom ', which is [0a 46 72 6f 6d 20].
  let start = 0
  let chunks: Uint8Array[] = [] // After the first iteration length >= 1.

  let progress = 0

  const getChunk = (endPos: number) => {
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

      const b = new Uint8Array(len) //Buffer.alloc(len)
      // chunks[0].copy(b, 0, start) // src.copy(target, targetStart?, sourceStart?, sourceEnd?)
      b.set(chunks[0].subarray(start))
      for (let i = 1; i < endChunkIdx; i++) {
        // chunks[i].copy(b, pos)
        b.set(chunks[i], pos)
        pos += chunks[i].length
      }
      // chunks[endChunkIdx].copy(b, pos, 0, endPos)
      b.set(chunks[endChunkIdx].subarray(0, endPos), pos)
      
      for (let i = 0; i < endChunkIdx; i++) {
        chunks.shift()
      }
      progress += len
      start = endPos
      return b
    } else {
      // Just return a slice from the original chunk set.
      const b = chunks[0].subarray(start, endPos)
      progress += endPos - start
      start = endPos
      return b
    }
  }

  let rbuf = new Uint8Array(6) // ring buffer with the last 6 bytes in the prev chunk
  let rnextidx = 0

  for await (const newChunk of readable) {
    // console.log('chunk', newChunk.length)
    // body += chunk
    const view = as_uint8_array(newChunk)
    chunks.push(view)

    // Scan for '\nFrom ' in the chunk list
    // let ci = 0
    // while (ci < view.byteLength) {
    for (let ci = 0; ci < view.byteLength; ci++) {
      rbuf[rnextidx] = view[ci]
      // console.log('pos', ci, 'rbuf', rbuf)
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
    yield {msg: getChunk(chunks[chunks.length-1].byteLength), progress}
  }
}

const splitFirst = (s: string, pattern: string) => {
  const idx = s.indexOf(pattern)
  if (idx < 0) return [s]
  else return [s.slice(0, idx), s.slice(idx + 1)]
}

// This trims extraneous '>' in '\n>+From ' patterns in mboxrd files
// const pattern = Buffer.from('>From ')
// const pattern = new TextEncoder().encode('>From ')
const FROM_PATTERN = new TextEncoder().encode('>From ')

const findSubstring = (buf: Uint8Array, pattern: Uint8Array, start: number = 0) => {
  assert(pattern.length > 0)

  let nextIdx = start
  while (true) {
    let idx = buf.indexOf(pattern[0], nextIdx)
    if (idx < 0) return idx // did not find the pattern. Return -1.

    // Check if the rest of the bytes match from idx
    let found = true
    for (let i = 1; i < pattern.length; i++) {
      if (buf[idx + i] !== pattern[i]) {
        found = false
        break
      }
    }

    if (found) return idx

    // keep lookin'.
    nextIdx = idx + 1
  }
}

const mboxrd_trim_from = (buf: Uint8Array, startIdx: number) => {
  let searchPos = startIdx + 1
  let shift = 0
  let copyTo = -1

  // Here we'll scan and compact the buffer inline using memmove.

  outer: while (searchPos < buf.length) {
    // We're looking for '\n>+From ' and we want to strip one of the > characters when we find it.
    const gtPos = findSubstring(buf, FROM_PATTERN, searchPos) // Index of the last >.
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
      buf.copyWithin(copyTo, copyTo+shift, p+2)
      // buf.copy(buf, copyTo, copyTo+shift, p+2) // src.copy(target, targetStart?, sourceStart?, sourceEnd?)
      // console.log('trim', shift)
    }
    copyTo = p + 2 - shift
    shift++
  }
  
  if (shift) {
    // assert(buf[copyTo] === 0x3e) // >
    buf.copyWithin(copyTo, copyTo+shift)
    // buf.copy(buf, copyTo, copyTo+shift)
    // console.log('trim', shift, copyTo)
  }

  return buf.subarray(startIdx, buf.length - shift)
}

const NEWLINE = '\n'.charCodeAt(0)
const dec = new TextDecoder()
export const mbox_to_eml = (_mbox_buf: ArrayBufferView, destructive = false) => {
  let mbox_buf = as_uint8_array(_mbox_buf)
  
  // The mbox string always starts with 'From '
  
  // Find the first line
  const end_line_1 = mbox_buf.indexOf(NEWLINE) // Its actually /r/n but this is fine.
  assert(end_line_1 > 0)
  const line_1 = dec.decode(mbox_buf.subarray(0, end_line_1 - 1)) // ignore the '\r' as well.
  // console.log(line_1)
  assert(line_1.startsWith('From '), 'mbox message does not start with from line')
  
  // The first line is 'From <id> <servertime>'. There are no spaces in the id.
  const id_and_time = line_1.slice('From '.length).toString()
  const [mboxFromAddress, time_str] = splitFirst(id_and_time, ' ')
  const receivedAt = (new Date(time_str)).toISOString()

  // const start_line_2 = mbox_buf.slice(end_line_1 + 1)

    // Check the message string matches what we expect.
    // const msg_str = mbox_buf.slice(end_line_1 + 1).toString('ascii')
    // const msg_str_sub = msg_str.replace(/^>(>*From )/mg, '$1')
    
  // Now we need to find \r\n>*From and remove one of the > characters.
  // I want to keep the data as a buffer, so I'm doing this the old fashioned way.
  // Could pretty easily do this in C instead.
  if (!destructive) mbox_buf = mbox_buf.slice()
  const body = mboxrd_trim_from(mbox_buf, end_line_1 + 1)
  // console.log(body.toString())

    // assert.deepStrictEqual(body.toString('ascii'), msg_str_sub)

  // const {json, attachments} = envelope_to_jmap(msg_str_sub, with_attachments)
  // json.receivedAt = receivedAt
  
  // For gmail, the mbox from address contains the ID of the message itself.
  // return {mboxFromAddress, json, attachments}
  return {body, mboxFromAddress, receivedAt}
}

export async function *mbox_each(stream: AsyncIterable<ArrayBufferView>) {
  for await (const {msg} of mbox_each_progress(stream)) {
    yield msg
  }
}

// module.exports = {mbox_each, mbox_each_progress, mbox_to_eml}
