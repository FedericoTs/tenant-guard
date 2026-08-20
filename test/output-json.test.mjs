/**
 * --json is a published contract, so these tests pin the SHAPE, not just that
 * it serialises. A field quietly changing meaning is the failure mode that
 * breaks somebody's pipeline three releases later.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { toJson, toJsonString, summarise, statusOf, SCHEMA_VERSION } from '../src/output/json.mjs';

const pass = { id: 'a', ok: true, summary: 'all good', scanned: 3, violations: [], notes: [] };
const fail = {
  id: 'b',
  ok: false,
  summary: '1 leak',
  scanned: 2,
  violations: [{ where: 'public.invoices', message: 'cross-tenant read', fix: 'enable RLS', kind: 'read' }],
  notes: [],
};
const skip = { id: 'c', ok: true, skipped: true, reason: 'no database configured', violations: [], notes: [] };

test('statusOf: a SKIP is never reported as a pass, even though ok is true', () => {
  assert.equal(statusOf(pass), 'pass');
  assert.equal(statusOf(fail), 'fail');
  assert.equal(statusOf(skip), 'skip'); // ok:true — the skip flag has to win
});

test('summarise: counts, and `ran` excludes skips', () => {
  const s = summarise([pass, fail, skip]);
  assert.equal(s.guards, 3);
  assert.equal(s.ran, 2); // not 3 — a skipped guard did not run
  assert.equal(s.passed, 1);
  assert.equal(s.failed, 1);
  assert.equal(s.skipped, 1);
  assert.equal(s.violations, 1);
  assert.equal(s.ok, false);
  assert.equal(s.exitCode, 1);
});

test('summarise: exitCode is 0 when nothing failed, even with skips', () => {
  const s = summarise([pass, skip]);
  assert.equal(s.ok, true);
  assert.equal(s.exitCode, 0);
});

test('summarise: tolerates an empty run', () => {
  const s = summarise([]);
  assert.deepEqual(s, { guards: 0, ran: 0, passed: 0, failed: 0, skipped: 0, violations: 0, notes: 0, ok: true, exitCode: 0 });
});

test('toJson: carries the schema version and the tool identity', () => {
  const j = toJson([pass], { command: 'run' });
  assert.equal(j.schemaVersion, SCHEMA_VERSION);
  assert.equal(j.tool.name, 'tenant-guard');
  assert.match(j.tool.version, /^\d+\.\d+\.\d+/);
  assert.equal(j.command, 'run');
});

test('toJson: `reason` is present on a skip and absent otherwise', () => {
  const j = toJson([pass, skip]);
  assert.equal(j.guards[0].reason, undefined);
  assert.equal(j.guards[1].reason, 'no database configured');
});

test('toJson: violations keep where/message/fix/kind and drop nothing else', () => {
  const j = toJson([fail]);
  assert.deepEqual(j.guards[0].violations, [
    { where: 'public.invoices', message: 'cross-tenant read', kind: 'read', fix: 'enable RLS' },
  ]);
});

test('toJson: a violation without a fix omits the key rather than emitting null', () => {
  const j = toJson([{ id: 'x', ok: false, summary: 's', violations: [{ where: 'w', message: 'm' }], notes: [] }]);
  assert.deepEqual(Object.keys(j.guards[0].violations[0]), ['where', 'message']);
});

test('toJson: notes survive — they never fail the build but they are still findings', () => {
  const withNote = { id: 'n', ok: true, summary: 's', violations: [], notes: [{ where: 'public.audit', message: 'no tenant column' }] };
  const j = toJson([withNote]);
  assert.deepEqual(j.guards[0].notes, [{ where: 'public.audit', message: 'no tenant column' }]);
  assert.equal(j.summary.notes, 1);
});

test('toJson: tolerates guards that report no violations/notes arrays at all', () => {
  const j = toJson([{ id: 'bare', ok: true, summary: 's' }]);
  assert.deepEqual(j.guards[0].violations, []);
  assert.deepEqual(j.guards[0].notes, []);
});

test('toJsonString: deterministic — the same run twice is byte-identical', () => {
  const a = toJsonString([pass, fail, skip], { command: 'all' });
  const b = toJsonString([pass, fail, skip], { command: 'all' });
  assert.equal(a, b); // no timestamps, no durations: a baseline can be committed and diffed
  assert.ok(a.endsWith('\n'));
});
