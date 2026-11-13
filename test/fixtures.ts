import fs from 'node:fs';
import path from 'node:path';

/**
 * Where the real captures live: by default the repo's parent directory, which holds `es-lab.jsonl` and
 * `SpriteTreeSamples/*.json`. They are not part of the repo (one is a capture of a private machine, the others are
 * third-party samples), so a fresh clone does not have them; the suites that need them skip.
 * `test/fixtures/synthetic-lab.jsonl` is in the repo and always there.
 */
export const FIXTURES_DIR: string =
  process.env.FIXTURES_DIR ?? path.resolve(__dirname, '../..');

export type RealFixtureName =
  | 'es-lab.jsonl'
  | 'atomic_stealer.json'
  | 'rustbucket.json'
  | 'shlayer.json'
  | 'spritetree_demo.json';
export type FixtureName = 'synthetic-lab.jsonl' | RealFixtureName;

export const REAL_FIXTURES: RealFixtureName[] =
  ['es-lab.jsonl', 'atomic_stealer.json', 'rustbucket.json', 'shlayer.json', 'spritetree_demo.json'];

/** Absolute path of a fixture; the real .json ones live under SpriteTreeSamples/, the synthetic one in test/fixtures/. */
export function fixture(name: FixtureName): string {
  if (name === 'synthetic-lab.jsonl') return path.resolve(__dirname, 'fixtures', name);
  return name.endsWith('.json')
    ? path.join(FIXTURES_DIR, 'SpriteTreeSamples', name)
    : path.join(FIXTURES_DIR, name);
}

/** True when every real capture is present; the real-capture suites run only then. */
export const hasRealCaptures: boolean = REAL_FIXTURES.every((n) => fs.existsSync(fixture(n)));

export function readLines(name: FixtureName): string[] {
  return fs.readFileSync(fixture(name), 'utf8').split('\n').filter((l) => l.length > 0);
}
