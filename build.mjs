// Bundles src/virustotal-community.ts into dist/pack.mjs — the single artifact the registry
// serves. Everything is inlined (the SDK is types plus identity helpers), because the module is
// fetched by URL in a Web Worker with no import map: any bare specifier left in it would fail.
//
// Same flags the frontend's scripts/build-packs.mjs uses, so the artifact is byte-compatible with
// how the other packs are produced:
//   esbuild --bundle --format=esm --target=es2022 --platform=browser --minify
//
// Usage: node build.mjs
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(here, 'dist'), { recursive: true });

execFileSync(
    'npx',
    [
        'esbuild',
        join(here, 'src', 'virustotal-community.ts'),
        '--bundle',
        '--format=esm',
        '--target=es2022',
        '--platform=browser',
        '--minify',
        '--legal-comments=inline', // never strip a licence header out of a pack
        '--log-level=warning',
        `--outfile=${join(here, 'dist', 'pack.mjs')}`,
    ],
    { stdio: 'inherit', cwd: here },
);

console.log('wrote dist/pack.mjs — run `node gen-manifest.mjs` next to refresh the manifest.');
