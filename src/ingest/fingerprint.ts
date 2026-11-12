const HEAD_BYTES = 1 << 20;

/** Two independent 32-bit FNV-1a lanes (different offset bases) = a 64-bit non-cryptographic hash. */
function fnv64Hex(bytes: Uint8Array): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193 ^ 0x9e3779b9;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    h1 = Math.imul(h1 ^ b, 0x01000193);
    h2 = Math.imul(h2 ^ b, 0x01000193) ^ (h2 >>> 15);
  }
  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return hex(h1) + hex(h2);
}

/**
 * Identity of a capture that survives the file growing (eslogger keeps appending):
 * hash of the first 1 MiB plus the first event's seq and time. crypto.subtle is
 * avoided on purpose; it is unavailable in insecure contexts such as file://.
 */
export async function fingerprint(
  blob: Blob,
  firstSeq: number | null,
  firstTime: string | null,
): Promise<string> {
  const head = new Uint8Array(await blob.slice(0, HEAD_BYTES).arrayBuffer());
  return `${fnv64Hex(head)}:${firstSeq}:${firstTime}`;
}
