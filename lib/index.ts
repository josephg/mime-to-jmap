
const modFn = require("./cyrus.js") as () => Promise<ModuleType>

type ptr = number

interface ModuleType {
  HEAPU8: Uint8Array,
  _xmalloc(len: number): ptr,
  _m_free(p: ptr): void,

  lengthBytesUTF8(s: string): number,
  stringToUTF8(s: string, ptr: ptr, numBytes: number): void,
  UTF8ToString(ptr: ptr, maxBytesToRead?: number): string,
  writeArrayToMemory(arr: ArrayBufferView | number[], ptr: ptr): void,

  _init(): void,
  onRuntimeInitialized?: () => void,

  // [k: string]: any
  ASAN_OPTIONS?: string

  _start_leaktrace(): void,

  /** struct cyrusmsg *msg_parse(const char *mime_text, size_t len) */
  _msg_parse(mime_text: ptr, len: number): ptr,

  /** void msg_free(struct cyrusmsg *msg) */
  _msg_free(msg: ptr): void,
  
  /** char *msg_to_json(struct cyrusmsg *msg, char *want_headers, char *want_bodyheaders) */
  _msg_to_json(msg: ptr, want_headers: ptr, want_bodyheaders: ptr): ptr,

  /** char *get_blob_space() */
  _get_blob_space(): ptr,

  /** const char *msg_get_blob(struct cyrusmsg *msg, char *blobId, size_t expectedSize) */
  _msg_get_blob(msg: ptr, blobId: ptr, expectedSize: number): ptr,

  /** returns true if there's an error. */
  _end_leaktrace_and_check(): number,
}

// Module['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1'
// Module['ASAN_OPTIONS'] = 'detect_leaks=1,print_stats=1,verbose=1,atexit=1'
// Module['ASAN_OPTIONS'] = 'print_stats=1'
//const to_jmap = Module.cwrap('to_jmap', 'string', ['string'])

//console.log(process.argv)

const assert = (cond: any, str?: string) => {
  if (!cond) throw Error(str || 'assertion failed')
}

let is_ready = false

let Module: ModuleType | undefined

export const ready = new Promise((resolve) => {
  modFn().then(mod => {
    Module = mod
    is_ready = true
    mod._init()
    resolve(mod)
  })
})

// const _arrayToHeap = (jsbuf) => {
//   const numBytes = jsbuf.length
//   const ptr = Module._xmalloc(numBytes);
//   Module.writeArrayToMemory(jsbuf, ptr)
//   return ptr
// }
const _strToHeap = (str: string) => {
  const numBytes = Module!.lengthBytesUTF8(str) + 1
  const ptr = Module!._xmalloc(numBytes)
  Module!.stringToUTF8(str, ptr, numBytes)
  return ptr
}

const copyFromHeap = (base: number, len: number) => {
  return Module!.HEAPU8.buffer.slice(base, base + len) // Returns an ArrayBuffer.
}
// const heapToBuf = (base, len) => {
//   const buf_slice = Buffer.from(Module.HEAPU8.buffer, base, len)
//   return Buffer.from(buf_slice) // Copy it
// }

/* Options:
  with_attachments: bool (default: false)
  want_headers: string[] (default: none). Extra headers to parse on the root object
  want_bodyheaders: string[] (default: none). Extra headers to parse on each body
*/

export interface JMAPMailOpts {
  /** Fetch full attachment blobs */
  with_attachments?: boolean,

  /** Eg ['header:X-Gmail-Labels:asText'] */
  want_headers?: string[],
  want_bodyheaders?: string[],
}

// mime_content is an arraybuffer, node buffer, data view or a string. (node buffers conform to ArrayBufferView.)
export const envelope_to_jmap = (mime_content: string | ArrayBuffer | ArrayBufferView, opts: JMAPMailOpts = {}) => {
  if (!Module) throw Error('You must wait for wasm module to be ready before calling this')

  // const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
  // console.log('SHA', hash, typeof mime_content === 'string' ? 'string' : Buffer.isBuffer(mime_content) ? 'buffer' : 'unknown', mime_content.length)

  // if (typeof mime_content === 'string') mime_content = Buffer.from(mime_content)

  Module._start_leaktrace()
  // console.log(mime_content)
  
  // First create a cyrusmsg* from whatever we got in as mime_content:
  let mime_ptr: number
  let mime_len: number
  if (typeof mime_content === 'string') {
    mime_len = (Module.lengthBytesUTF8(mime_content) as number)
    // stringToUTF8 adds a '\0' which is included in the length.
    mime_ptr = Module._xmalloc(mime_len) + 1
    Module.stringToUTF8(mime_content, mime_ptr, mime_len + 1)
  } else {
    mime_len = mime_content.byteLength
    mime_ptr = Module._xmalloc(mime_len);
    Module.writeArrayToMemory(mime_content instanceof ArrayBuffer
        ? new Uint8Array(mime_content)
        : mime_content,
      mime_ptr)
  }

  // process.stderr.write('-----\n')
  const msg = Module._msg_parse(mime_ptr, mime_len)
  // console.log('ptr', mime_ptr, msg)
  Module._m_free(mime_ptr)
  if (msg === 0) {
    // Error handling message
    // const hash = crypto.createHash('sha1').update(mime_content).digest('hex')
    // fs.writeFileSync('error.eml', mime_content)
    // throw Error('Parse error reading message - message written to error.eml with hash ' + hash)
    throw Error('Parse error reading message')
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
  let attachments: {[blobId: string]: ArrayBuffer} | undefined
  if (opts.with_attachments) {
    attachments = {}
    const blobid_ptr = Module._get_blob_space();
    for (const {blobId, name, size} of json.attachments) {
      // console.log('blob', blobId, name, size)
      if (blobId.length !== 41) throw Error('unexpected blob length')
      // const blob_buf = Buffer.from(blobId, 'ascii')
      // The blob id is always ascii, and we'd get a buffer overrun if its not treated as such.
      const blob_buf = new Uint8Array(41).map((_, i) => blobId.charCodeAt(i))
      Module.writeArrayToMemory(blob_buf, blobid_ptr)

      const blob_ptr = Module._msg_get_blob(msg, 0, size);
      attachments[blobId] = copyFromHeap(blob_ptr, size)
      //console.log(blob_ptr)
    }
  }

  Module._msg_free(msg)

  if (Module._end_leaktrace_and_check()) {
    // fs.writeFileSync('leaky.eml', mime_content)
    throw Error('Memory leak! Contents written to leaky.eml')
  }

  return {json, attachments}
}

export {mbox_each, mbox_each_progress, mbox_to_eml} from './mbox_utils'

// module.exports = {
//   ready,
//   envelope_to_jmap,
//   ...require('./mbox_utils')
// }
