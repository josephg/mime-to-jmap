const fs = require('fs')
const crypto = require('crypto')
const Module = require("./mimer.js")
// Module['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1'
// Module['ASAN_OPTIONS'] = 'detect_leaks=1,print_stats=1,verbose=1,atexit=1'
Module['ASAN_OPTIONS'] = 'print_stats=1'
//const to_jmap = Module.cwrap('to_jmap', 'string', ['string'])

//console.log(process.argv)

const assert = (cond, str) => {
  if (!cond) throw Error(str || 'assertion failed')
}

const ready = new Promise((resolve) => {
  Module.onRuntimeInitialized = resolve
})

function _arrayToHeap(jsbuf){
  const numBytes = jsbuf.length
  const ptr = Module._malloc(numBytes);
  Module.HEAPU8.set(typeof jsbuf === 'string' ? Buffer.from(jsbuf, 'ascii') : jsbuf, ptr)
  return ptr
}

const heapToBuf = (base, len) => {
  const buf_slice = Buffer.from(Module.HEAPU8.buffer, base, len)
  return Buffer.from(buf_slice) // Copy it
}

// mime_content is a buffer or a string
const envelope_to_jmap = (mime_content, with_attachments) => {
  // const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
  // console.log('SHA', hash, typeof mime_content === 'string' ? 'string' : Buffer.isBuffer(mime_content) ? 'buffer' : 'unknown', mime_content.length)

  if (typeof mime_content === 'string') mime_content = Buffer.from(mime_content)

  assert(!Module._assert_no_leaks())
  // console.log(mime_content)
  
  // First create a cyrusmsg*
  const mime_ptr = _arrayToHeap(mime_content)
  // process.stderr.write('-----\n')
  const msg = Module._msg_parse(mime_ptr, mime_content.length)
  // console.log('ptr', mime_ptr, msg)
  Module._free(mime_ptr)
  if (msg === 0) {
    // Error handling message
    const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
    fs.writeFileSync('error.eml', mime_content)
    throw Error('Parse error reading message - message written to error.eml with hash ' + hash)
  }

  // Ok now get JSON out
  // const json_str = Module.ccall('msg_to_json', 'string', ['number'], [msg])
  const json_str_ptr = Module._msg_to_json(msg)
  const json_str = Module.UTF8ToString(json_str_ptr)
  const json = JSON.parse(json_str)
  Module._m_free(json_str_ptr)

  // ... And the attachments!
  let attachments
  if (with_attachments) {
    attachments = {}
    const blobid_ptr = Module._get_blob_space();
    for (const {blobId, name, size} of json.attachments) {
      // console.log('blob', blobId, name, size)
      if (blobId.length !== 41) throw Error('unexpected blob length')
      const blob_buf = Buffer.from(blobId, 'ascii')
      Module.HEAPU8.set(blob_buf, blobid_ptr)
      const blob_ptr = Module._msg_get_blob(msg, null, size);
      attachments[blobId] = heapToBuf(blob_ptr, size)
      //console.log(blob_ptr)
    }
  }

  Module._msg_free(msg)

  // Module._leak_check()
  if (Module._assert_no_leaks()) {
    fs.writeFileSync('leaky.eml', mime_content)
    throw Error('Memory leak! Contents written to leaky.eml')
  }

  return {json, attachments}
}

module.exports = {
  ready,
  envelope_to_jmap,
  ...require('./mbox_utils')
}

if (require.main === module) {
  ready.then(async () => {
    for (let i = 2; i < process.argv.length; i++) {
      const buf = fs.readFileSync(process.argv[i])
      //console.log(JSON.parse(to_jmap(buf)))

      for (let iter = 0; iter < 1; iter++) {
        const {json, attachments} = envelope_to_jmap(buf)
        // console.log(process.argv[i])
        // Module._leak_check()
        console.dir(json)
      }
      // console.dir(json ? json : 'ERROR', {depth:null})
  
      // for (const {name, blobId, type} of json.attachments) {
      //   const data = attachments[blobId]
      //   console.log('Got file', name, data.length, 'of type', type)
      //   fs.writeFileSync('xx_' + name, data)
      // }
    }
  })
}

// process.on('exit', () => {
//   // console.log('leak check')
//   // Module._leak_check()
// })