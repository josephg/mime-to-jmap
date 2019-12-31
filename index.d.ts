/// <reference types="node" />

import {ReadStream} from 'fs'

export const ready: Promise<void>

interface JMAPMailOpts {
  /** Fetch full attachment blobs */
  with_attachments?: boolean,

  /** Eg ['header:X-Gmail-Labels:asText'] */
  want_headers?: string[],
  want_bodyheaders?: string[],
}

export function envelope_to_jmap(mime_content: Buffer | string, opts?: JMAPMailOpts): {
  json: any,
  attachments?: {[blobId: string]: Buffer}
}

export function mbox_each(stream: ReadStream): AsyncGenerator<Buffer>
export function mbox_each_progress(stream: ReadStream): AsyncGenerator<{msg: Buffer, progress: number}>

/** Parse an mboxrd message object into headers and processed body. Consumed passed buffer. */
export const mbox_to_eml: (buf_owned: Buffer) => {
  mboxFromAddress: string,
  receivedAt: string, // ISO string for JMAP conformance.
  body: Buffer,
}
