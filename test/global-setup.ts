import { FIXTURES_DIR, hasRealCaptures } from './fixtures';

/** One note, before any test file runs, when the real captures are missing. */
export default function setup(): void {
  if (hasRealCaptures) return;
  console.log(
    `\n[tests] Real captures not found in ${FIXTURES_DIR} (es-lab.jsonl and SpriteTreeSamples/*.json): ` +
    'the real-capture tests are skipped; the synthetic fixture (test/fixtures/synthetic-lab.jsonl) tests still run. ' +
    'Set FIXTURES_DIR to run them all.\n',
  );
}
