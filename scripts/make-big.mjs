// Builds scratch/big.jsonl (gitignored): es-lab.jsonl concatenated COPIES times (default 18, ~500 MB),
// with n * 10_000_000 added to global_seq_num in copy n, for the spec §9 large-capture check.
// Usage: node scripts/make-big.mjs [path/to/es-lab.jsonl] [copies]
// Note: every copy repeats the same pids and audit tokens, so the model sees the same
// processes again and again; it exercises load volume, not 18x as many distinct processes.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = path.resolve(process.argv[2] ?? path.join(root, '..', 'es-lab.jsonl'));
const copies = Number(process.argv[3] ?? 18);
const out = path.join(root, 'scratch', 'big.jsonl');

const lines = fs.readFileSync(src, 'utf8').split('\n').filter((l) => l.length > 0);
const SEQ = /"global_seq_num":(\d+)/;
fs.mkdirSync(path.dirname(out), { recursive: true });
const fd = fs.openSync(out, 'w');
let bytes = 0;
for (let n = 0; n < copies; n++) {
  const add = n * 10_000_000;
  const chunk = lines.map((l) => l.replace(SEQ, (_, s) => `"global_seq_num":${Number(s) + add}`)).join('\n') + '\n';
  bytes += fs.writeSync(fd, chunk);
}
fs.closeSync(fd);
console.log(`wrote ${out}: ${copies} copies, ${lines.length * copies} events, ${(bytes / 1e6).toFixed(1)} MB`);
