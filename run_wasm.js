const fs = require('fs')
const Module = require("./mimer")
//const to_jmap = Module.cwrap('to_jmap', 'string', ['string'])

//console.log(process.argv)

const ready = new Promise((resolve) => {
  Module.onRuntimeInitialized = resolve
})

function _arrayToHeap(jsbuf){
  const numBytes = jsbuf.length
  const ptr = Module._malloc(numBytes);
  const heapBytes = new Uint8Array(Module.HEAPU8.buffer, ptr, numBytes);
  heapBytes.set(new Uint8Array(jsbuf.buffer));
  return heapBytes;
}

function _freeArray(heapBytes){
  Module._free(heapBytes.byteOffset);
}

const to_jmap = (mime_content) => {
  const heapBytes = _arrayToHeap(mime_content);
  const ret = Module.ccall('to_jmap', 'string', ['number','number'],
    [heapBytes.byteOffset, mime_content.length]);
  _freeArray(heapBytes);
  return ret;
};

ready.then(async () => {
  const buf = fs.readFileSync(process.argv[2])
  console.log(JSON.parse(to_jmap(buf)))
})


