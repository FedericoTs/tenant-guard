/**
 * The package version, read from package.json at runtime.
 *
 * Kept in one place because three surfaces need it — `--version`, the `tool`
 * block of `--json`, and the SARIF driver — and a hardcoded copy would drift
 * from package.json on the first release someone forgets to update it.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

function read() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    return JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = read();
