/**
 * CLI packaging audit — two ways the binary broke its own documented contract.
 *
 * Both are about the exit-code promise the CLI prints in its own HELP text:
 *
 *     0  every guard that ran passed        (a skip is not a pass)
 *     1  at least one guard failed
 *     2  bad usage — unknown command or option
 *
 * The value of `1` is that CI can trust it to mean "you have a tenant leak".
 * Anything returning 1 for a reason that is NOT a leak — a crash, a typo —
 * erodes that from one side; anything returning 0 while silently dropping the
 * report the operator asked for erodes it from the other.
 *
 * These spawn the real binary against examples/leaky-demo (three known real
 * violations), so a 1 here is a genuine finding rather than a mock.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'tenant-guard.mjs');
const DEMO = join(ROOT, 'examples', 'leaky-demo');

/** Run the real binary; NO_COLOR keeps assertions free of ANSI escapes. */
function cli(args, opts = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    cwd: opts.cwd ?? DEMO,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
}

// ── a command name that collides with Object.prototype ───────────────
// RUNTIME_COMMANDS is a plain object literal, so a bare `RUNTIME_COMMANDS[cmd]`
// lookup is truthy for every inherited key. Measured before the fix: all the
// names below passed the dispatch check, destructured `fn` as undefined, and
// died with an uncaught "TypeError: fn is not a function" — exit 1, i.e. CI
// reads a typo as a tenant leak. `flibble` (the case test/cli.test.mjs already
// covers) is not a prototype key, so the old suite never saw this.

const PROTOTYPE_KEYS = [
  'constructor',
  'toString',
  'valueOf',
  'hasOwnProperty',
  '__proto__',
  'isPrototypeOf',
  'propertyIsEnumerable',
];

for (const key of PROTOTYPE_KEYS) {
  test(`"${key}" is an unknown command (exit 2), not a crash (exit 1)`, () => {
    const { code, err } = cli([key]);
    assert.equal(code, 2, `expected 2 = bad usage, got ${code}; stderr: ${err}`);
    assert.match(err, /Unknown command/);
    assert.doesNotMatch(err, /TypeError/); // an uncaught throw is never the usage path
  });
}

test('real commands still dispatch — the own-property check did not break the table', () => {
  // `prove` is a runtime command: with no database URL it must reach its OWN
  // skip path, not fall through to "Unknown command". This is the calibration
  // half of the fix — narrowing the lookup must not narrow the command set.
  const { code, out, err } = cli(['prove']);
  assert.doesNotMatch(err, /Unknown command/);
  assert.notEqual(code, 2);
  assert.match(out, /skip/i); // the "a skip is not a pass" hint proves the guard ran
});

// ── an output flag with an empty value ───────────────────────────────
// `--json=` parsed to '', which is falsy, so emit()'s `if (flags.json)` skipped
// the writer entirely. Measured before the fix, in examples/leaky-demo:
// `run --json= --sarif= --markdown=` printed the human report, exited 1, wrote
// no files, and printed none of the "→ wrote" lines. Exit code intact, reports
// gone. Realistic trigger: `--json=$SOME_UNSET_VAR` in a hand-written CI step,
// or a plain typo.

const EMPTY_VALUE_FLAGS = ['--json', '--sarif', '--markdown', '--md'];

for (const flag of EMPTY_VALUE_FLAGS) {
  test(`"${flag}=" is a usage error (exit 2), not a silently dropped report`, () => {
    const { code, err } = cli(['run', `${flag}=`]);
    assert.equal(code, 2, `expected 2 = bad usage, got ${code}; stderr: ${err}`);
    assert.match(err, new RegExp(`\\${flag} needs a file path`));
  });
}

test('a whitespace-only path is rejected too, rather than reaching writeFileSync', () => {
  // '   ' is truthy, so it sailed past the falsy check straight into
  // writeFileSync. Measured pre-fix: this did NOT throw — it wrote a real
  // 3990-byte JSON report into examples/leaky-demo/"   ", a file named three
  // spaces, invisible in most directory listings. The operator gets an exit
  // code and no findable report. A real path never trims to empty, so folding
  // this into the same usage error costs no legitimate invocation.
  const { code, err } = cli(['run', '--json=   ']);
  assert.equal(code, 2);
  assert.match(err, /needs a file path/);
});

test('an empty output value never leaves a run reporting success', () => {
  // The sharpest phrasing of the bug: asking for three reports and getting none
  // of them must not look like a clean run. Run from ROOT, where the static
  // guards find nothing to say, so the old code exited a confident 0.
  const { code } = cli(['run', '--json=', '--sarif=', '--markdown='], { cwd: ROOT });
  assert.notEqual(code, 0);
});

test('real file paths and bare flags are untouched by the empty-value check', () => {
  // The calibration half: the fix must not make a correct invocation fail.
  const dir = mkdtempSync(join(tmpdir(), 'tg-pack-'));
  try {
    const { code } = cli([
      'run',
      `--json=${join(dir, 'a.json')}`,
      `--sarif=${join(dir, 'b.sarif')}`,
      `--markdown=${join(dir, 'c.md')}`,
    ]);
    assert.equal(code, 1); // the demo really does leak — 1 is the finding, not the flags
    for (const f of ['a.json', 'b.sarif', 'c.md']) {
      assert.ok(existsSync(join(dir, f)), `${f} was not written`);
    }
    assert.equal(readdirSync(dir).length, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // Bare `--json` (no '=') still means stdout, and stdout stays pure JSON.
  const bare = cli(['run', '--json']);
  assert.equal(bare.code, 1);
  JSON.parse(bare.out); // throws if a usage error leaked onto stdout
});
