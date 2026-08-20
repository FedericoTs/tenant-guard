/**
 * End-to-end CLI tests: flags, exit codes, and — the one that actually matters
 * for CI — that `--json` puts NOTHING on stdout except JSON.
 *
 * These spawn the real binary against examples/leaky-demo, which has two known
 * violations, so the exit code under test is a genuine 1 rather than a mock.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'tenant-guard.mjs');
const DEMO = join(ROOT, 'examples', 'leaky-demo');

/** Run the CLI in the leaky demo; NO_COLOR keeps assertions free of escapes. */
function cli(args, opts = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    cwd: opts.cwd ?? DEMO,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
}

// ── basics ───────────────────────────────────────────────────────────

test('--version prints just the version', () => {
  const { code, out } = cli(['--version']);
  assert.equal(code, 0);
  assert.match(out.trim(), /^\d+\.\d+\.\d+/);
});

test('--help exits 0 and documents the exit codes', () => {
  const { code, out } = cli(['--help']);
  assert.equal(code, 0);
  assert.match(out, /USAGE/);
  assert.match(out, /EXIT CODES/);
  assert.match(out, /--sarif/);
});

test('an unknown command exits 2 and points at --help', () => {
  const { code, err } = cli(['flibble']);
  assert.equal(code, 2); // 2 = bad usage, distinct from 1 = a guard failed
  assert.match(err, /Unknown command/);
  assert.match(err, /--help/);
});

test('an unknown option exits 2 rather than being silently ignored', () => {
  const { code, err } = cli(['run', '--jsonn']);
  assert.equal(code, 2);
  assert.match(err, /Unknown option/);
});

// ── exit codes are the contract ──────────────────────────────────────

test('the exit code is identical in every output format', () => {
  const human = cli(['run']).code;
  const json = cli(['run', '--json']).code;
  const quiet = cli(['run', '--quiet']).code;
  assert.equal(human, 1); // the demo really does leak
  assert.equal(json, 1);
  assert.equal(quiet, 1);
});

// ── stdout purity ────────────────────────────────────────────────────

test('--json puts NOTHING on stdout but JSON', () => {
  const { out } = cli(['run', '--json']);
  const parsed = JSON.parse(out); // would throw on a banner or a stray hint
  assert.equal(parsed.schemaVersion, 1);
  assert.equal(parsed.summary.failed, 2);
});

test('--sarif puts NOTHING on stdout but SARIF', () => {
  const { out } = cli(['run', '--sarif']);
  const parsed = JSON.parse(out);
  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs[0].results.length, 2);
});

test('--json and --sarif cannot both take stdout — it exits 2 instead of interleaving', () => {
  const { code, err } = cli(['run', '--json', '--sarif']);
  assert.equal(code, 2);
  assert.match(err, /--json and --sarif cannot both write to stdout/);
});

test('the stdout-conflict message stays grammatical with three formats', () => {
  const { code, err } = cli(['run', '--json', '--sarif', '--markdown']);
  assert.equal(code, 2);
  assert.match(err, /--json, --sarif and --markdown cannot all write to stdout/);
});

test('one format on stdout and the rest in files is fine', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-cli-'));
  try {
    const r = cli(['run', '--json', `--sarif=${join(dir, 's.sarif')}`, `--markdown=${join(dir, 'm.md')}`]);
    assert.equal(r.code, 1);
    assert.ok(JSON.parse(r.out).summary); // stdout is still pure JSON
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── files ────────────────────────────────────────────────────────────

test('--json=FILE writes the file AND keeps the human report', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-cli-'));
  try {
    const out = join(dir, 'result.json');
    const r = cli(['run', `--json=${out}`]);
    assert.equal(r.code, 1);
    assert.match(r.out, /guard\(s\) failed/); // the human report is still there
    assert.match(r.out, /wrote JSON/);
    const parsed = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(parsed.summary.failed, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an ABSOLUTE output path is honoured, not glued onto the cwd', () => {
  // CI runners hand out absolute scratch dirs ($RUNNER_TEMP), so this is the
  // normal case in the environment the flag exists for.
  const dir = mkdtempSync(join(tmpdir(), 'tg-cli-'));
  try {
    const out = join(dir, 'nested', 'deep.sarif');
    const r = cli(['run', `--sarif=${out}`]);
    assert.equal(r.code, 1);
    const parsed = JSON.parse(readFileSync(out, 'utf8')); // also proves mkdir -p
    assert.equal(parsed.version, '2.1.0');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--quiet writes the file and prints nothing at all', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-cli-'));
  try {
    const out = join(dir, 'q.json');
    const r = cli(['run', '--quiet', `--json=${out}`]);
    assert.equal(r.code, 1);
    assert.equal(r.out, '');
    assert.ok(JSON.parse(readFileSync(out, 'utf8')).summary);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── colour ───────────────────────────────────────────────────────────

test('FORCE_COLOR emits ANSI even when stdout is a pipe', () => {
  const r = spawnSync(process.execPath, [BIN, 'run'], {
    cwd: DEMO, encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '', FORCE_COLOR: '1' },
  });
  assert.match(r.stdout, /\u001b\[3[12]m/); // red or green
});

test('NO_COLOR beats FORCE_COLOR — the accessibility opt-out wins', () => {
  const r = spawnSync(process.execPath, [BIN, 'run'], {
    cwd: DEMO, encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '1' },
  });
  assert.doesNotMatch(r.stdout, /\u001b\[/);
});

// ── catalogue ────────────────────────────────────────────────────────

test('list --json emits the guard catalogue as data', () => {
  const { code, out } = cli(['list', '--json']);
  assert.equal(code, 0);
  const parsed = JSON.parse(out);
  assert.ok(parsed.guards.length >= 16);
  for (const g of parsed.guards) {
    assert.ok(g.id && g.title && g.why, `guard ${g.id} is missing metadata`);
  }
});

test('the SARIF from a run with skips records every skip as a notification', () => {
  // `all` with no database configured: 13 guards skip, and a green-looking
  // upload must still carry the reason each one did not run.
  const { out } = cli(['all', '--sarif']);
  const parsed = JSON.parse(out);
  const notes = parsed.runs[0].invocations[0].toolConfigurationNotifications;
  assert.ok(notes.length > 0);
  assert.match(notes[0].message.text, /A skip is not a pass/);
});
