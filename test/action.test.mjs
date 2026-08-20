/**
 * Tests the GitHub Action's shell logic by EXECUTING it, under the exact shell
 * GitHub uses: `bash --noprofile --norc -e -o pipefail`.
 *
 * This exists because the same class of bug shipped twice. GitHub runs
 * composite `run` steps with **errexit already on**, so the CLI exiting 1 —
 * which is its normal, expected behaviour when a guard fails — killed the step
 * before a single output was written, and before the SARIF upload could run.
 * Not writing `set -e` does not turn off the inherited one.
 *
 * Nothing else in the suite covers action.yml: it is YAML and shell, invisible
 * to every unit test, and a composite action cannot be verified any other way
 * short of a real runner.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
/** Bash chokes on backslashes inside double quotes; it takes C:/… happily. */
const slash = (p) => p.replace(/\\/g, '/');

/**
 * Pull one step's `run:` body out of action.yml as text.
 *
 * Deliberately not a YAML parse: the package ships zero dependencies and a YAML
 * library is not worth taking on for this. The block is found by its `id:` and
 * dedented by its own indentation.
 */
export function extractRunStep(yamlText, stepId) {
  const lines = yamlText.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === `id: ${stepId}`);
  if (start === -1) throw new Error(`no step with id: ${stepId}`);
  const runAt = lines.findIndex((l, i) => i > start && l.trim() === 'run: |');
  if (runAt === -1) throw new Error(`step ${stepId} has no "run: |" block`);

  const body = [];
  const indent = (lines[runAt].match(/^(\s*)/)[1] + '  ').length;
  for (let i = runAt + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') { body.push(''); continue; }
    if (line.search(/\S/) < indent) break; // dedented out of the block
    body.push(line.slice(indent));
  }
  return body.join('\n');
}

const ACTION = readFileSync(join(ROOT, 'action.yml'), 'utf8');
const bashOk = (() => {
  const r = spawnSync('bash', ['-c', 'echo ok'], { encoding: 'utf8' });
  return !r.error && r.status === 0;
})();

test('extractRunStep: finds the step body and dedents it', () => {
  const body = extractRunStep(ACTION, 'tenant-guard');
  assert.match(body, /^set -uo pipefail/m);
  assert.match(body, /node "\$TG_CLI"/);
  assert.doesNotMatch(body, /^\s{4}set -uo/m); // dedented, not left indented
});

test('the run step disables errexit around the CLI call', () => {
  // Kept alongside the executable test below because it names the invariant.
  // Matched line-by-line on purpose: a substring search is satisfied by the
  // COMMENT explaining `set +e`, which is exactly how a first draft of this
  // test passed against an action.yml that had the fix removed.
  const lines = extractRunStep(ACTION, 'tenant-guard').split('\n');
  const call = lines.findIndex((l) => l.includes('node "$TG_CLI"'));
  assert.ok(call !== -1, 'the step must invoke the CLI');

  let off = -1;
  for (let i = 0; i < call; i++) if (lines[i].trim() === 'set +e') off = i;
  assert.ok(off !== -1, 'the CLI call must be preceded by a bare `set +e` line');

  assert.equal(lines[call + 1].trim(), 'CODE=$?', 'the exit code must be captured immediately');
});

test('a guard FAILURE must not kill the step — outputs still get written', { skip: !bashOk && 'bash not available' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-action-'));
  try {
    const script = join(dir, 'step.sh');
    writeFileSync(script, extractRunStep(ACTION, 'tenant-guard'), { encoding: 'utf8' });

    const out = join(dir, 'output.txt');
    writeFileSync(out, '');
    writeFileSync(join(dir, 'summary.md'), '');

    const r = spawnSync(
      'bash',
      ['--noprofile', '--norc', '-e', '-o', 'pipefail', slash(script)],
      {
        // examples/leaky-demo has two real violations, so the CLI exits 1 here.
        cwd: join(ROOT, 'examples', 'leaky-demo'),
        encoding: 'utf8',
        env: {
          ...process.env,
          RUNNER_TEMP: slash(dir),
          GITHUB_OUTPUT: slash(out),
          GITHUB_STEP_SUMMARY: slash(join(dir, 'summary.md')),
          GITHUB_ACTION: 'selftest',
          TG_COMMAND: 'run',
          TG_SUMMARY: 'true',
          TG_CLI: slash(join(ROOT, 'bin', 'tenant-guard.mjs')),
          NO_COLOR: '1',
        },
      },
    );

    assert.equal(r.status, 0, `the step must survive a guard failure; stderr: ${r.stderr}`);

    const outputs = readFileSync(out, 'utf8');
    assert.match(outputs, /^exit-code=1$/m);   // the CLI really did fail
    assert.match(outputs, /^result=fail$/m);
    assert.match(outputs, /^sarif-exists=true$/m); // …and still produced SARIF
    assert.match(outputs, /^sarif-file=/m);
    assert.match(outputs, /^json-file=/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a PASSING run reports result=pass', { skip: !bashOk && 'bash not available' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'tg-action-'));
  try {
    const script = join(dir, 'step.sh');
    writeFileSync(script, extractRunStep(ACTION, 'tenant-guard'), { encoding: 'utf8' });
    const out = join(dir, 'output.txt');
    writeFileSync(out, '');
    writeFileSync(join(dir, 'summary.md'), '');

    const r = spawnSync(
      'bash',
      ['--noprofile', '--norc', '-e', '-o', 'pipefail', slash(script)],
      {
        // The repo root has no migrations or routes, so every guard skips → 0.
        cwd: ROOT,
        encoding: 'utf8',
        env: {
          ...process.env,
          RUNNER_TEMP: slash(dir),
          GITHUB_OUTPUT: slash(out),
          GITHUB_STEP_SUMMARY: slash(join(dir, 'summary.md')),
          GITHUB_ACTION: 'selftest',
          TG_COMMAND: 'run',
          TG_SUMMARY: 'true',
          TG_CLI: slash(join(ROOT, 'bin', 'tenant-guard.mjs')),
          NO_COLOR: '1',
        },
      },
    );

    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const outputs = readFileSync(out, 'utf8');
    assert.match(outputs, /^exit-code=0$/m);
    assert.match(outputs, /^result=pass$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
