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

let is_ready = false

const ready = new Promise((resolve) => {
  Module.onRuntimeInitialized = () => {
    Module._init()
    is_ready = true
    resolve()
  }
})

const _arrayToHeap = (jsbuf) => {
  const numBytes = jsbuf.length
  const ptr = Module._xmalloc(numBytes);
  Module.HEAPU8.set(jsbuf, ptr)
  return ptr
}
const _strToHeap = (str) => {
  const numBytes = str.length + 1
  const ptr = Module._xmalloc(numBytes);
  Module.HEAPU8.set(Buffer.from(str, 'ascii'), ptr)
  Module.HEAPU8[ptr + str.length] = 0
  return ptr
}

const heapToBuf = (base, len) => {
  const buf_slice = Buffer.from(Module.HEAPU8.buffer, base, len)
  return Buffer.from(buf_slice) // Copy it
}

/* Options:
  with_attachments: bool (default: false)
  want_headers: string[] (default: none). Extra headers to parse on the root object
  want_bodyheaders: string[] (default: none). Extra headers to parse on each body
*/

// mime_content is a buffer or a string
const envelope_to_jmap = (mime_content, opts = {}) => {
  assert(is_ready, 'You must wait for wasm module to be ready before calling this')

  // const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
  // console.log('SHA', hash, typeof mime_content === 'string' ? 'string' : Buffer.isBuffer(mime_content) ? 'buffer' : 'unknown', mime_content.length)

  if (typeof mime_content === 'string') mime_content = Buffer.from(mime_content)

  Module._start_leaktrace()
  // console.log(mime_content)
  
  // First create a cyrusmsg*
  const mime_ptr = _arrayToHeap(mime_content)
  // process.stderr.write('-----\n')
  const msg = Module._msg_parse(mime_ptr, mime_content.length)
  // console.log('ptr', mime_ptr, msg)
  Module._m_free(mime_ptr)
  if (msg === 0) {
    // Error handling message
    const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
    fs.writeFileSync('error.eml', mime_content)
    throw Error('Parse error reading message - message written to error.eml with hash ' + hash)
  }

  // Ok now get JSON out
  // const json_str = Module.ccall('msg_to_json', 'string', ['number'], [msg])

  // console.log('x', opts.want_headers.join('\n'))
  const want_headers = opts.want_headers ? _strToHeap(opts.want_headers.join('\n')) : 0
  const want_bodyheaders = opts.want_bodyheaders ? _strToHeap(opts.want_bodyheaders.join('\n')) : 0
  const json_str_ptr = Module._msg_to_json(msg, want_headers, want_bodyheaders)
  const json_str = Module.UTF8ToString(json_str_ptr)
  const json = JSON.parse(json_str)

  if (want_headers) Module._m_free(want_headers)
  if (want_bodyheaders) Module._m_free(want_bodyheaders)
  Module._m_free(json_str_ptr)

  // ... And the attachments!
  let attachments
  if (opts.with_attachments) {
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

  if (Module._end_leaktrace_and_check()) {
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
