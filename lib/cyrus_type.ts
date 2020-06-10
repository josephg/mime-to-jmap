
export type ptr = number

export interface ModuleType {
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