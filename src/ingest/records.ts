/**
 * How a capture file holds its events. `lines`: one JSON object per line, as `eslogger` and Mac Monitor's JSONL export
 * write them. `objects`: pretty-printed objects, one after another (Mac Monitor's JSON export) or in a JSON array, so a
 * record spans many lines.
 */
export type Layout = 'lines' | 'objects';

/** How much of the head detectLayout reads to find the first line. */
const DETECT_BYTES = 64 << 10;

/**
 * `objects` when the file starts with `[`, or with a line that is only `{` (every JSON encoder's pretty output starts
 * that way, while a JSONL line holds its keys after the brace); `lines` otherwise, which keeps every existing JSONL
 * capture on the line reader and its identity. Leading whitespace and a byte order mark are skipped.
 */
export async function detectLayout(blob: Blob): Promise<Layout> {
  const head = new TextDecoder('utf-8').decode(await blob.slice(0, DETECT_BYTES).arrayBuffer());
  const text = head.replace(/^[﻿\s]+/, '');
  if (text.startsWith('[')) return 'objects';
  const nl = text.indexOf('\n');
  const first = (nl === -1 ? text : text.slice(0, nl)).trim();
  return first === '{' ? 'objects' : 'lines';
}

const enum C { OpenBrace = 0x7b, CloseBrace = 0x7d, OpenBracket = 0x5b, CloseBracket = 0x5d, Quote = 0x22,
  Backslash = 0x5c, Comma = 0x2c, Newline = 0x0a, Return = 0x0d, Space = 0x20, Tab = 0x09 }

/**
 * Stream a Blob as its top-level JSON objects, whatever separates them: newlines, nothing, or the brackets and commas
 * of a JSON array. `complete` is false for an object cut short and for text that is not an object (reported line by
 * line), so the caller can count them as unreadable.
 *
 * The scanner tracks strings and their escapes, and the nesting of objects and arrays. A record cut short does not
 * swallow the rest of the file: a raw newline cannot occur inside a JSON string, so one ends the record, and a `{` at
 * the very start of a line inside a record starts a new one (pretty-printers indent nested objects).
 */
export async function streamObjects(
  blob: Blob,
  onRecord: (text: string, complete: boolean) => void,
  onProgress?: (bytes: number, total: number) => void,
  chunkSize = 4 << 20,
): Promise<void> {
  const decoder = new TextDecoder('utf-8');
  const total = blob.size;
  let carry = '';           // the start of the record (or junk line) being read, from earlier chunks
  let depth = 0;            // open objects and arrays of the record being read; 0 between records
  let junk = false;         // reading text between records that is not an object, up to the end of its line
  let inString = false;
  let escaped = false;
  let lineStart = true;     // the previous character was a newline (or this is the start of the file)

  const scan = (text: string) => {
    let start = 0;          // where the current record or junk starts in `text`, when it started in this chunk
    const take = (end: number): string => {
      const t = carry + text.slice(start, end);
      carry = '';
      return t;
    };
    for (let i = 0; i < text.length; i++) {
      const ch = text.charCodeAt(i);
      const atLineStart = lineStart;
      lineStart = ch === C.Newline;
      if (junk) {
        if (ch === C.Newline) {
          const t = take(i).replace(/\r$/, '');
          if (t.trim() !== '') onRecord(t, false);
          junk = false;
        }
        continue;
      }
      if (depth === 0) {
        if (ch === C.OpenBrace) { depth = 1; start = i; }
        else if (ch !== C.Space && ch !== C.Tab && ch !== C.Newline && ch !== C.Return && ch !== C.Comma
          && ch !== C.OpenBracket && ch !== C.CloseBracket && ch !== 0xfeff) { junk = true; start = i; }
        continue;
      }
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === C.Backslash) escaped = true;
        else if (ch === C.Quote) inString = false;
        else if (ch === C.Newline) {   // a raw newline: this record was cut inside a string
          onRecord(take(i), false);
          inString = false; depth = 0;
        }
        continue;
      }
      if (ch === C.Quote) inString = true;
      else if (ch === C.OpenBrace || ch === C.OpenBracket) {
        if (ch === C.OpenBrace && atLineStart) {   // a new record: the one being read was cut short
          onRecord(take(i), false);
          depth = 1; start = i;
        } else depth++;
      } else if (ch === C.CloseBrace || ch === C.CloseBracket) {
        if (--depth === 0) onRecord(take(i + 1), true);
      }
    }
    if (depth > 0 || junk) carry += text.slice(start);
  };

  for (let off = 0; off < total; off += chunkSize) {
    const buf = await blob.slice(off, Math.min(off + chunkSize, total)).arrayBuffer();
    scan(decoder.decode(buf, { stream: true }));
    onProgress?.(Math.min(off + chunkSize, total), total);
  }
  scan(decoder.decode());
  const rest = carry.replace(/\r$/, '');
  if (rest.trim() !== '') onRecord(rest, false);
}
