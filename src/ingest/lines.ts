/**
 * Stream a Blob line by line without holding the whole text in memory.
 * Reads `chunkSize`-byte slices, decodes with a streaming TextDecoder (so a
 * multi-byte character split across slices stays intact) and carries the
 * partial last line over to the next slice. Empty lines are skipped.
 */
export async function streamLines(
  blob: Blob,
  onLine: (l: string) => void,
  onProgress?: (bytes: number, total: number) => void,
  chunkSize = 4 << 20,
): Promise<void> {
  const decoder = new TextDecoder('utf-8');
  const total = blob.size;
  let carry = '';
  const emit = (text: string) => {
    let start = 0;
    for (let nl = text.indexOf('\n', start); nl !== -1; nl = text.indexOf('\n', start)) {
      const line = carry + text.slice(start, nl);
      carry = '';
      if (line.length > 0) onLine(line);
      start = nl + 1;
    }
    carry += text.slice(start);
  };
  for (let off = 0; off < total; off += chunkSize) {
    const buf = await blob.slice(off, Math.min(off + chunkSize, total)).arrayBuffer();
    emit(decoder.decode(buf, { stream: true }));
    onProgress?.(Math.min(off + chunkSize, total), total);
  }
  emit(decoder.decode());
  if (carry.length > 0) onLine(carry);
}
