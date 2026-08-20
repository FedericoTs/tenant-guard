/**
 * SARIF tests. The interesting half is `locationsFor`: SARIF demands a file,
 * most of these guards find things in a DATABASE, and the rule this project
 * holds to is that it never invents a location it does not have.
 *
 * examples/leaky-demo is used as the on-disk fixture because it is a real
 * repo shape (config + migrations + routes) that already ships with the package.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { toSarif, locationsFor, rulesFor, fingerprint } from '../src/output/sarif.mjs';

const DEMO = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples', 'leaky-demo');
const ctx = {
  cwd: DEMO,
  migrationsDir: 'supabase/migrations',
  anchorCandidates: ['tenant-guard.config.json', 'package.json'],
};

// ── locations ────────────────────────────────────────────────────────

test('locationsFor: route-org-scoping reports a repo path — used as-is', () => {
  const locs = locationsFor('route-org-scoping', 'src/app/api/invoices/[id]/route.ts', ctx);
  assert.deepEqual(locs, [{ uri: 'src/app/api/invoices/[id]/route.ts' }]);
});

test('locationsFor: a migration guard reports a bare filename — gets the migrations dir prefixed', () => {
  const locs = locationsFor('definer-grants', '200_add_reset_helper.sql', ctx);
  assert.deepEqual(locs, [{ uri: 'supabase/migrations/200_add_reset_helper.sql' }]);
});

test('locationsFor: migration-collisions names every colliding file — one location each', () => {
  const locs = locationsFor('migration-collisions', '200_add_reset_helper.sql, 201_seed.sql', ctx);
  assert.deepEqual(locs, [
    { uri: 'supabase/migrations/200_add_reset_helper.sql' },
    { uri: 'supabase/migrations/201_seed.sql' },
  ]);
});

test('locationsFor: a file that is not on disk yields NO location rather than a broken pointer', () => {
  // GitHub silently drops results pointing at missing files, which would turn a
  // real finding into a green run. Emitting nothing keeps it visible at the root.
  assert.deepEqual(locationsFor('route-org-scoping', 'src/app/api/ghost/route.ts', ctx), []);
  assert.deepEqual(locationsFor('definer-grants', '999_nope.sql', ctx), []);
});

test('locationsFor: a runtime finding anchors at the config file — the file you would edit to allowlist it', () => {
  const locs = locationsFor('rls-proof', 'public.invoices', ctx);
  assert.deepEqual(locs, [{ uri: 'tenant-guard.config.json' }]);
});

test('locationsFor: with no anchor candidate on disk, a runtime finding has no location at all', () => {
  const locs = locationsFor('rls-proof', 'public.invoices', { ...ctx, anchorCandidates: ['nope.json'] });
  assert.deepEqual(locs, []);
});

test('locationsFor: backslash paths are normalised to forward slashes (SARIF URIs)', () => {
  const locs = locationsFor('definer-grants', '200_add_reset_helper.sql', { ...ctx, migrationsDir: 'supabase\\migrations' });
  assert.deepEqual(locs, [{ uri: 'supabase/migrations/200_add_reset_helper.sql' }]);
});

// ── document ─────────────────────────────────────────────────────────

const proofLeak = {
  id: 'rls-proof',
  ok: false,
  summary: '1 leak',
  violations: [{ where: 'public.invoices', message: 'tenant A read tenant B rows', fix: 'enable RLS' }],
  notes: [{ where: 'public.audit', message: 'could not prove' }],
};
const skipped = { id: 'rls-drift', ok: true, skipped: true, reason: 'no database configured', violations: [], notes: [] };

test('toSarif: a well-formed 2.1.0 document with one run', () => {
  const s = toSarif([proofLeak], { command: 'prove', ...ctx });
  assert.equal(s.version, '2.1.0');
  assert.match(s.$schema, /sarif-2\.1/);
  assert.equal(s.runs.length, 1);
  assert.equal(s.runs[0].tool.driver.name, 'tenant-guard');
});

test('toSarif: findings do NOT mark the invocation unsuccessful', () => {
  // executionSuccessful:false means "the tool crashed" and makes GitHub discard
  // the whole run — exactly backwards for a guard that found something.
  const s = toSarif([proofLeak], { command: 'prove', ...ctx });
  assert.equal(s.runs[0].invocations[0].executionSuccessful, true);
});

test('toSarif: a violation is level error, a note is level note', () => {
  const results = toSarif([proofLeak], { command: 'prove', ...ctx }).runs[0].results;
  assert.equal(results.length, 2);
  assert.equal(results[0].level, 'error');
  assert.equal(results[1].level, 'note');
  assert.equal(results[1].properties.note, true);
});

test('toSarif: the fix is carried into the message — the finding is useless without it', () => {
  const [first] = toSarif([proofLeak], { command: 'prove', ...ctx }).runs[0].results;
  assert.match(first.message.text, /tenant A read tenant B rows/);
  assert.match(first.message.text, /Fix: enable RLS/);
});

test('toSarif: a runtime finding names the database object in logicalLocations', () => {
  const [first] = toSarif([proofLeak], { command: 'prove', ...ctx }).runs[0].results;
  assert.equal(first.locations[0].physicalLocation.artifactLocation.uri, 'tenant-guard.config.json');
  assert.equal(first.locations[0].logicalLocations[0].name, 'public.invoices');
});

test('toSarif: a static finding does NOT repeat its own path as a logical location', () => {
  const routeLeak = {
    id: 'route-org-scoping', ok: false, summary: '1',
    violations: [{ where: 'src/app/api/invoices/[id]/route.ts', message: 'bare id' }], notes: [],
  };
  const [first] = toSarif([routeLeak], { command: 'run', ...ctx }).runs[0].results;
  assert.equal(first.locations[0].physicalLocation.artifactLocation.uri, 'src/app/api/invoices/[id]/route.ts');
  assert.equal(first.locations[0].logicalLocations, undefined);
});

test('toSarif: every skip becomes a notification — a green upload must still say what did not run', () => {
  const s = toSarif([skipped], { command: 'all', ...ctx });
  const notes = s.runs[0].invocations[0].toolConfigurationNotifications;
  assert.equal(notes.length, 1);
  assert.match(notes[0].message.text, /SKIPPED/);
  assert.match(notes[0].message.text, /no database configured/);
  assert.match(notes[0].message.text, /not a pass/);
});

// ── rules ────────────────────────────────────────────────────────────

test('rulesFor: one rule per distinct guard, built from the guard metadata', () => {
  const metaById = new Map([['rls-proof', { id: 'rls-proof', title: 'Runtime RLS isolation proof', why: 'Proves isolation.' }]]);
  const rules = rulesFor([proofLeak, proofLeak], metaById);
  assert.equal(rules.length, 1); // deduped
  assert.equal(rules[0].id, 'rls-proof');
  assert.equal(rules[0].name, 'RlsProof');
  assert.equal(rules[0].shortDescription.text, 'Runtime RLS isolation proof');
  assert.equal(rules[0].fullDescription.text, 'Proves isolation.');
  assert.equal(rules[0].defaultConfiguration.level, 'error');
});

test('rulesFor: a guard with no metadata still produces a valid rule', () => {
  const rules = rulesFor([{ id: 'mystery', violations: [], notes: [] }], new Map());
  assert.equal(rules[0].id, 'mystery');
  assert.equal(rules[0].shortDescription.text, 'mystery');
});

// ── fingerprints ─────────────────────────────────────────────────────

test('fingerprint: stable across runs, distinct per finding', () => {
  const a = fingerprint('rls-proof', 'public.invoices', 'leak');
  assert.equal(a, fingerprint('rls-proof', 'public.invoices', 'leak'));
  assert.notEqual(a, fingerprint('rls-proof', 'public.orders', 'leak'));
  assert.notEqual(a, fingerprint('view-isolation', 'public.invoices', 'leak'));
  assert.match(a, /^[0-9a-f]{16}$/);
});
