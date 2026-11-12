import fs from 'node:fs';
import path from 'node:path';

export const FIXTURES_DIR: string =
  process.env.FIXTURES_DIR ?? path.resolve(__dirname, '../..');

export type FixtureName =
  | 'es-lab.jsonl'
  | 'atomic_stealer.json'
  | 'rustbucket.json'
  | 'shlayer.json'
  | 'spritetree_demo.json';

/** Absolute path of a fixture; the .json ones live under SpriteTreeSamples/. */
export function fixture(name: FixtureName): string {
  return name.endsWith('.json')
    ? path.join(FIXTURES_DIR, 'SpriteTreeSamples', name)
    : path.join(FIXTURES_DIR, name);
}

export function readLines(name: FixtureName): string[] {
  return fs.readFileSync(fixture(name), 'utf8').split('\n').filter((l) => l.length > 0);
}
