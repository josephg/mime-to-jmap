/// <reference types="node" />

export const ready: Promise<void>

export function envelope_to_jmap(mime_content: Buffer | string, with_attachments?: boolean): {
  json: any,
  attachments?: {[blobId: string]: Buffer}
}
export function mbox_message_to_jmap(mime_content: Buffer | string, with_attachments?: boolean): {
  json: any,
  mboxFromAddress: string,
  attachments?: {[blobId: string]: Buffer}
}
