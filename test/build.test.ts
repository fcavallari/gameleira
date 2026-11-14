import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from 'vitest';

test('single self-contained file with CSP', () => {
  const html = fs.readFileSync('dist/index.html', 'utf8');
  expect(html).toContain("connect-src 'none'");
  expect(html).toContain("base-uri 'none'");
  expect(html).toContain("form-action 'none'");
  expect(html).toContain('<title>Gameleira</title>');
  expect(html).not.toContain('fetch('); // the module-preload polyfill is off: nothing in the page fetches
  expect(html).not.toMatch(/<script[^>]+src=/);
  expect(html).not.toMatch(/<link[^>]+rel="stylesheet"[^>]+href=/);
  expect(html).not.toContain('__FIXTURES_DIR__'); // dev autoload stripped
  expect(fs.readdirSync('dist')).toEqual(['index.html']);
  expect(html).toContain('worker');
  expect(html).toContain('No eslogger or Mac Monitor events found'); // the ingest worker (runLoad) is bundled
  // The dev fixture path must not leak. (A bare '/Users/' check is impossible: normPath() in the rules
  // legitimately contains that literal.)
  expect(html).not.toContain(path.resolve(__dirname, '..', '..'));
  expect(html).not.toContain('/@fs');
});

test('dev-only fixture autoload is stripped from the production build', () => {
  const html = fs.readFileSync('dist/index.html', 'utf8');
  // Unique strings from src/ui/dev.ts and the `?load=` effect in session-context.tsx. If
  // import.meta.env.DEV stops being folded to false, these leak and this test fails.
  for (const s of [
    'dev fixtures are not available',
    'bad fixture name',
    'could not fetch fixture',
    'SpriteTreeSamples',
    'location.search',
    '?load=',
  ]) {
    expect(html, s).not.toContain(s);
  }
  expect(html).not.toMatch(/URLSearchParams\([^)]*search/);
  expect(html).not.toMatch(/\.get\(["']load["']\)/);
});
