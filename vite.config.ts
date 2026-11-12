import path from 'node:path';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

const CSP =
  "default-src 'none'; script-src 'unsafe-inline' blob:; worker-src blob:; " +
  "style-src 'unsafe-inline'; img-src data:; connect-src 'none'";

// Production page carries a CSP that forbids all network access. The tag is
// spliced in as raw text: Vite's tag serializer would entity-escape the quotes
// (&#39;), which browsers decode but which makes the policy unreadable on disk.
const cspPlugin = (): Plugin => ({
  name: 'eslogger-viewer-csp',
  apply: 'build',
  transformIndexHtml: {
    order: 'post',
    handler: (html) => {
      if (!html.includes('<head>')) throw new Error('CSP plugin: no <head> in index.html');
      return html.replace(
        '<head>',
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}">`,
      );
    },
  },
});

export default defineConfig({
  plugins: [react(), viteSingleFile(), cspPlugin()],
  server: { fs: { allow: [path.resolve(import.meta.dirname, '..'), import.meta.dirname] } },
  define: { __FIXTURES_DIR__: JSON.stringify(path.resolve(import.meta.dirname, '..')) },
  test: { environment: 'node' },
});
