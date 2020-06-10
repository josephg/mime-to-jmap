// This function contains methods and code to interact with the wasm module

import { ModuleType } from './cyrus_type'

let mod: ModuleType | undefined
export const _setMod = (_mod: ModuleType) => {
  mod = _mod
}

// Module['ASAN_OPTIONS'] = 'detect_stack_use_after_return=1'
// Module['ASAN_OPTIONS'] = 'detect_leaks=1,print_stats=1,verbose=1,atexit=1'
// Module['ASAN_OPTIONS'] = 'print_stats=1'
//const to_jmap = Module.cwrap('to_jmap', 'string', ['string'])

const _strToHeap = (str: string) => {
  const numBytes = mod!.lengthBytesUTF8(str) + 1
  const ptr = mod!._xmalloc(numBytes)
  mod!.stringToUTF8(str, ptr, numBytes)
  return ptr
}

const copyFromHeap = (base: number, len: number) => {
  return mod!.HEAPU8.buffer.slice(base, base + len) // Returns an ArrayBuffer.
}

export interface JMAPMailOpts {
  /** Fetch full attachment blobs. Default: false */
  with_attachments?: boolean,

  /** Extra headers to parse on the root object. Eg ['header:X-Gmail-Labels:asText'] */
  want_headers?: string[],
  /** Extra headers to parse on each body */
  want_bodyheaders?: string[],
}

// mime_content is an arraybuffer, node buffer, data view or a string. (node buffers conform to ArrayBufferView.)
export const envelope_to_jmap = (mime_content: string | ArrayBuffer | ArrayBufferView, opts: JMAPMailOpts = {}) => {
  if (!mod) throw Error('You must wait for wasm module to be ready before calling this')

  // This is a no-op in release mode.
  mod._start_leaktrace()
  
  // First create a cyrusmsg* from whatever we got in as mime_content:
  let mime_ptr: number
  let mime_len: number
  if (typeof mime_content === 'string') {
    mime_len = (mod.lengthBytesUTF8(mime_content) as number)
    // stringToUTF8 adds a '\0' which is included in the length.
    mime_ptr = mod._xmalloc(mime_len) + 1
    mod.stringToUTF8(mime_content, mime_ptr, mime_len + 1)
  } else {
    mime_len = mime_content.byteLength
    mime_ptr = mod._xmalloc(mime_len);
    mod.writeArrayToMemory(mime_content instanceof ArrayBuffer
        ? new Uint8Array(mime_content)
        : mime_content,
      mime_ptr)
  }

  // process.stderr.write('-----\n')
  const msg = mod._msg_parse(mime_ptr, mime_len)
  // console.log('ptr', mime_ptr, msg)
  mod._m_free(mime_ptr)
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
  const json_str_ptr = mod._msg_to_json(msg, want_headers, want_bodyheaders)
  const json_str = mod.UTF8ToString(json_str_ptr)
  const json = JSON.parse(json_str)

  if (want_headers) mod._m_free(want_headers)
  if (want_bodyheaders) mod._m_free(want_bodyheaders)
  mod._m_free(json_str_ptr)

  // ... And the attachments!
  let attachments: {[blobId: string]: ArrayBuffer} | undefined
  if (opts.with_attachments) {
    attachments = {}
    const blobid_ptr = mod._get_blob_space();
    for (const {blobId, name, size} of json.attachments) {
      // console.log('blob', blobId, name, size)
      if (blobId.length !== 41) throw Error('unexpected blob length')
      // const blob_buf = Buffer.from(blobId, 'ascii')
      // The blob id is always ascii, and we'd get a buffer overrun if its not treated as such.
      const blob_buf = new Uint8Array(41).map((_, i) => blobId.charCodeAt(i))
      mod.writeArrayToMemory(blob_buf, blobid_ptr)

      const blob_ptr = mod._msg_get_blob(msg, 0, size);
      attachments[blobId] = copyFromHeap(blob_ptr, size)
      //console.log(blob_ptr)
    }
  }

  mod._msg_free(msg)

  if (mod._end_leaktrace_and_check()) {
    // fs.writeFileSync('leaky.eml', mime_content)
    throw Error('Memory leak! Contents written to leaky.eml')
  }

  return {json, attachments}
}
