/**
 * Dev-only: fetch a fixture from the fixtures directory through Vite's /@fs route (`?load=es-lab.jsonl`).
 * `import.meta.env.DEV` is false in a production build, so the body (and the local path in
 * `__FIXTURES_DIR__`, which vite.config.ts defines for `serve` only) is dead-code-eliminated.
 */
export async function fetchDevFixture(name: string): Promise<File> {
  if (!import.meta.env.DEV) throw new Error('dev fixtures are not available in this build');
  if (!/^[\w.-]+\.jsonl?$/.test(name)) throw new Error(`bad fixture name: ${name}`);
  const dir = name.endsWith('.json') ? `${__FIXTURES_DIR__}/SpriteTreeSamples` : __FIXTURES_DIR__;
  const res = await fetch(`/@fs${dir}/${name}`);
  if (!res.ok) throw new Error(`could not fetch fixture ${name}: HTTP ${res.status}`);
  return new File([await res.blob()], name);
}
