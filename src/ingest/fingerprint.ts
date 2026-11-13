/** The hash covers this many complete lines (fewer when the file has fewer). */
const HEAD_LINES = 200;
/** Never read more than this much of the head, however long the lines are. */
const HEAD_BYTES = 4 << 20;
const CHUNK = 256 << 10;

/** Two independent 32-bit FNV-1a lanes (different offset bases) = a 64-bit non-cryptographic hash. */
class Fnv64 {
  private h1 = 0x811c9dc5;
  private h2 = 0x01000193 ^ 0x9e3779b9;

  add(bytes: Uint8Array): void {
    let { h1, h2 } = this;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i]!;
      h1 = Math.imul(h1 ^ b, 0x01000193);
      h2 = Math.imul(h2 ^ b, 0x01000193) ^ (h2 >>> 15);
    }
    this.h1 = h1;
    this.h2 = h2;
  }

  hex(): string {
    const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
    return hex(this.h1) + hex(this.h2);
  }
}

const NEWLINE = 0x0a;
const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  if (a.length === 0) return b;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

/**
 * Identity of a capture that survives the file growing (eslogger keeps appending): a hash of the first 200 complete
 * lines, plus the first event's seq and time. Complete lines, not a byte count: whatever the file's size at the time,
 * the first lines are the same, so a capture that was loaded when it was small and is loaded again later keeps its
 * verdicts. A last line cut in the middle is left out. Reads at most 4 MiB. A capture with fewer than 200 lines is
 * hashed whole, so it changes identity if it grows before reaching 200. A file with no complete line is hashed as far
 * as it goes. crypto.subtle is avoided on purpose; it is unavailable in insecure contexts such as file://.
 */
export async function fingerprint(
  blob: Blob,
  firstSeq: number | null,
  firstTime: string | null,
): Promise<string> {
  const hash = new Fnv64();
  const limit = Math.min(blob.size, HEAD_BYTES);
  let pending: Uint8Array = new Uint8Array(0);   // bytes of a line whose end has not been read yet
  let lines = 0;
  for (let off = 0; off < limit && lines < HEAD_LINES; ) {
    const end = Math.min(off + CHUNK, limit);
    pending = concat(pending, new Uint8Array(await blob.slice(off, end).arrayBuffer()));
    off = end;
    let start = 0;
    for (let nl = pending.indexOf(NEWLINE, start); nl !== -1 && lines < HEAD_LINES; nl = pending.indexOf(NEWLINE, start)) {
      if (nl > start) {   // empty lines are not lines (the loader skips them too)
        hash.add(pending.subarray(start, nl));
        hash.add(Uint8Array.of(NEWLINE));
        lines++;
      }
      start = nl + 1;
    }
    pending = pending.subarray(start);
  }
  if (lines === 0) hash.add(pending);
  return `${hash.hex()}:${firstSeq}:${firstTime}`;
}
