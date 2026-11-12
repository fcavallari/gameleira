import fs from 'node:fs';
import { expect, test } from 'vitest';

test('single self-contained file with CSP', () => {
  const html = fs.readFileSync('dist/index.html', 'utf8');
  expect(html).toContain("connect-src 'none'");
  expect(html).not.toMatch(/<script[^>]+src=/);
  expect(html).not.toMatch(/<link[^>]+rel="stylesheet"[^>]+href=/);
  expect(html).not.toContain('__FIXTURES_DIR__'); // dev autoload stripped
  expect(fs.readdirSync('dist')).toEqual(['index.html']);
  expect(html).toContain('worker');
});
